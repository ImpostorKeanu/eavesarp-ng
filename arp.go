package eavesarp_ng

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
	"net"
	"time"
)

const (
	maxArpRetries = 3
	arpTimeout    = 4 * time.Second
)

var (
	anyAddr = make([]byte, 4)
)

type (
	// ActiveArp represents an ARP request that we're waiting on a
	// response for.
	ActiveArp struct {
		// TargetIpRec is the database record associated with the
		// ARP target.
		TargetIpRec Ip
		// Cancel is any cancel function that should be called
		// later.
		Cancel context.CancelFunc
	}

	// arpStringAddrs consists of network addresses in string format that
	// were extracted from an ARP packet.
	arpStringAddrs struct {
		SenIp, SenHw, TarIp, TarHw string
	}

	// SendArpCfg represent values needed to send an ARP request/response.
	//
	// Instances of this type are sent to a SenderServer routine that writes
	// ARP requests and responses to the wire.
	//
	// Any name prefixed with "Req" indicates a field relevant only to ARP
	// requests, specifically:
	//
	// - ReqCtx
	// - ReqMaxRetries
	// - ReqTimeout
	SendArpCfg struct {
		// Handle that will be used to send the ARP request/response.
		Handle *pcap.Handle
		// Operation indicating the type of packet, i.e., request or
		// response. See layers.ARP for more information.
		Operation uint64
		SenderHw  net.HardwareAddr
		SenderIp  net.IP
		TargetHw  net.HardwareAddr
		TargetIp  net.IP
		// ReqCtx allows one to set a context for the request, enabling
		// timeouts and cancellation. This field is relevant only for ARP
		// requests.
		//
		// ActiveArp records can retain the cancel function (ActiveArp.Cancel)
		// for use upon receiving a response.
		ReqCtx context.Context
		// ReqMaxRetries indicates the maximum number of retries for an
		// ARP request.
		ReqMaxRetries int
		// ReqTimeout determines the duration of time before an ARP request
		// without a response is canceled.
		ReqTimeout time.Duration
	}

	// ArpSpoofHandler defines the signature for functions that handle
	// packets that are received after poisoning a sender's ARP table.
	ArpSpoofHandler func(packet gopacket.Packet)

	// AttackSnacCfg is used to configure an ARP spoofing attack.
	AttackSnacCfg struct {
		// Calling the Cancel func associated with Ctx stops the
		// ARP spoofing attack.
		Ctx      context.Context
		SenderIp net.IP
		TargetIp net.IP
		// Handlers are functions that each packet is passed to.
		Handlers   []ArpSpoofHandler
		downstream net.IP
	}
)

// newUnpackedArp converts binary address values to string.
func newUnpackedArp(arp *layers.ARP) arpStringAddrs {
	return arpStringAddrs{
		SenIp: net.IP(arp.SourceProtAddress).To4().String(),
		SenHw: net.HardwareAddr(arp.SourceHwAddress).String(),
		TarIp: net.IP(arp.DstProtAddress).To4().String(),
		TarHw: net.HardwareAddr(arp.DstHwAddress).String(),
	}
}

// SendArp sends an ARP request described by SendArpCfg.
func SendArp(cfg Cfg, sA SendArpCfg) (err error) {
	// SOURCE: https://github.com/google/gopacket/blob/master/examples/arpscan/arpscan.go

	logFields := []zap.Field{
		zap.String("senderIp", sA.SenderIp.String()), zap.String("senderMac", sA.SenderHw.String()),
		zap.String("targetIp", sA.TargetIp.String()), zap.String("targetMac", sA.TargetHw.String())}

	ethDstHw := sA.TargetHw
	arpDstHw := sA.TargetHw

	if sA.Operation == layers.ARPReply {

		if sA.TargetHw == nil {
			return errors.New("sending arp replies requires a target hardware address value")
		}
		logFields = append(logFields, zap.String("arpOperation", "reply"))

	} else {

		if sA.TargetHw == nil {
			// looks like we're broadcasting a request
			ethDstHw = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
			arpDstHw = net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		}

		aa := cfg.arp.active.Get(sA.TargetIp.String())
		if aa == nil {
			err = errors.New("active arp record not found")
			cfg.log.Error("failed to find active arp record", zap.Error(err))
			return
		}

		// should always have a request timeout greater than zero
		if sA.ReqTimeout == 0 {
			sA.ReqTimeout = arpTimeout
		}

		var (
			ctx    context.Context
			cancel context.CancelFunc
		)
		ctx = sA.ReqCtx
		if ctx == nil {
			ctx = context.Background()
		}
		ctx, cancel = context.WithTimeout(ctx, sA.ReqTimeout)

		// set an afterfunc that recursively retries arp resolution
		// until retries is exhausted
		context.AfterFunc(ctx, func() {
			cancel()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				if sA.ReqMaxRetries > 0 {
					sA.ReqMaxRetries--
					fields := logFields[:]
					fields = append(fields, zap.Int("remainingRetries", sA.ReqMaxRetries))
					cfg.log.Info("retrying arp", fields...)
					if err := SendArp(cfg, sA); err != nil {
						logFields = append(logFields, zap.Error(err))
						cfg.log.Error("error retrying arp", logFields...)
					}
					return
				}
				cfg.log.Info("never received arp response", logFields...)
			}
			if err := SetArpResolved(cfg.db, aa.TargetIpRec.Id); err != nil {
				cfg.log.Error("failed to set arp as resolved for ip", logFields...)
			}
			cfg.arp.active.Delete(aa.TargetIpRec.Value)
		})
	}

	eth := layers.Ethernet{
		SrcMAC:       sA.SenderHw,
		DstMAC:       ethDstHw,
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         uint16(sA.Operation),
		SourceHwAddress:   sA.SenderHw,
		SourceProtAddress: sA.SenderIp.To4(),
		DstHwAddress:      arpDstHw,
		DstProtAddress:    sA.TargetIp.To4(),
	}
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	buff := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buff, opts, &eth, &arp)

	cfg.log.Debug("sent arp", logFields...)
	if err != nil {
		cfg.log.Error("error serializing packet", zap.Error(err))
		return fmt.Errorf("failed to build arp packet: %w", err)
	} else if err = sA.Handle.WritePacketData(buff.Bytes()); err != nil {
		logFields = append(logFields, zap.Error(err))
		cfg.log.Error("error writing packet data", logFields...)
		return fmt.Errorf("failed to send arp packet: %w", err)
	}

	return
}

// handleWatchArpPacket handles a packet received by WatchArp.
//
// resolvedTargets tracks which target MAC addresses have been
// actively resolved, allowing us to avoid duplicate resolution
// attempts. This function has side effects on resolvedTargets.
func handleWatchArpPacket(cfg Cfg, handle *pcap.Handle, packet gopacket.Packet) (err error) {

	arpL := GetArpLayer(packet)
	if arpL == nil {
		return
	}
	sAddrs := newUnpackedArp(arpL)

	if bytes.Equal(cfg.iface.HardwareAddr, arpL.SourceHwAddress) {
		// ignore arp requests from our nic
		return
	}

	switch arpL.Operation {
	case layers.ARPRequest:

		//======================================
		// HANDLE PASSIVELY CAPTURED ARP REQUEST
		//======================================

		if !cfg.ipNet.Contains(arpL.DstProtAddress) || !cfg.ipNet.Contains(arpL.SourceProtAddress) {
			// ignore arp requests for addresses outside of our broadcast domain
			// TODO make this configurable....it should be optional
			return
		} else if bytes.Equal(arpL.SourceProtAddress, anyAddr) {
			// ignore arp requests from 0.0.0.0
			// TODO make this configurable....it should be optional
			return
		} else if cfg.ipNet.IP.Equal(arpL.DstProtAddress) {
			// capture ARP requests for senders wanting our mac address
			if _, srcIp, e := sAddrs.getOrCreateSenderDbValues(cfg, PassiveArpMeth); e != nil {
				err = e
				return
			} else if srcIp.IsNew {
				cfg.log.Info("new ip requested our mac", zap.String("ip", srcIp.Value))
			}
			return
		}

		var senIp, tarIp *Ip
		if _, senIp, tarIp, err = sAddrs.getOrCreateSnifferDbValues(cfg, PassiveArpMeth); err != nil {
			cfg.log.Error("failed to get sniffer db values", zap.Error(err))
			return
		}

		if senIp.IsNew {
			cfg.log.Info("new sender ip discovered passively", zap.String("ip", senIp.Value))
		}
		if tarIp.IsNew {
			cfg.log.Info("new target ip discovered passively", zap.String("ip", tarIp.Value))
		}

		//====================
		// INCREMENT ARP COUNT
		//====================

		var arpCount int
		arpCount, err = IncArpCount(cfg.db, senIp.Id, tarIp.Id)
		if err != nil {
			cfg.log.Error("failed to increment arp count",
				zap.String("senderIp", sAddrs.SenIp),
				zap.String("senderMac", sAddrs.SenHw),
				zap.String("targetIp", sAddrs.TarIp),
				zap.Error(err))
			return
		} else if arpCount == 1 {
			cfg.log.Info("new conversation discovered",
				zap.String("senderIp", sAddrs.SenIp),
				zap.String("senderMac", sAddrs.SenHw),
				zap.String("targetIp", sAddrs.TarIp))
		}

		//==================
		// DO ARP RESOLUTION
		//==================

		if tarIp.MacId == nil && !tarIp.ArpResolved && cfg.arp.active.Get(tarIp.Value) == nil {

			// SendArp will set ctx and Cancel
			// - We set this here to avoid duplicate resolution attempts, but
			//   let SendArp set the timeout to avoid race conditions
			cfg.arp.active.Set(tarIp.Value, &ActiveArp{
				TargetIpRec: *tarIp,
			})

			go func() {
				cfg.arp.ch <- SendArpCfg{
					Handle:        handle,
					Operation:     layers.ARPRequest,
					SenderHw:      cfg.iface.HardwareAddr,
					SenderIp:      cfg.ipNet.IP.To4(),
					TargetIp:      arpL.DstProtAddress,
					ReqCtx:        nil,
					ReqMaxRetries: maxArpRetries,
				}
			}()

		}

		//===================
		// DO NAME RESOLUTION
		//===================

		// skip name resolution AfterF excess failures
		if cfg.dns.failCount.Exceeded() {
			return
		}

		// determine which ips to reverse resolve
		var toResolve []*Ip
		for _, ip := range []*Ip{senIp, tarIp} {
			if !ip.PtrResolved && cfg.dns.active.Get(FmtDnsKey(ip.Value, PtrDnsKind)) == nil {
				cfg.log.Info("reverse dns resolving", zap.String("ip", ip.Value))
				toResolve = append(toResolve, ip)
			}
		}

		if len(toResolve) == 0 {
			return
		}

		// reverse resolve each ip
		go func() {
			for _, ip := range toResolve {
				dArgs := DoDnsCfg{
					Kind:   PtrDnsKind,
					Target: ip.Value,
					FailureF: func(e error) {
						if err := SetPtrResolved(cfg.db, *ip); err != nil {
							cfg.dns.active.Delete(FmtDnsKey(ip.Value, PtrDnsKind))
							cfg.log.Error("failed to set ptr to resolved", zap.String("ip", ip.Value), zap.Error(err))
							return
						}
						cfg.dns.active.Delete(FmtDnsKey(ip.Value, PtrDnsKind))
					},
					AfterF: func(names []string) {
						if err := SetPtrResolved(cfg.db, *ip); err != nil {
							cfg.dns.active.Delete(FmtDnsKey(ip.Value, PtrDnsKind))
							cfg.log.Error("failed to set ptr to resolved", zap.String("ip", ip.Value), zap.Error(err))
							return
						}
						for _, name := range names {
							cfg.log.Info("reverse dns resolution found", zap.String("ip", ip.Value), zap.String("name", name))
							handlePtrName(cfg, 10, handlePtrNameArgs[DoDnsCfg, ActiveArp]{
								ip:         ip,
								name:       name,
								srcIfaceIp: cfg.ipNet.IP.To4(),
								srcIfaceHw: cfg.iface.HardwareAddr,
								handle:     handle,
							})
						}
						cfg.dns.active.Delete(FmtDnsKey(ip.Value, PtrDnsKind))
					},
				}
				cfg.dns.active.Set(FmtDnsKey(ip.Value, PtrDnsKind), &dArgs)
				cfg.dns.ch <- dArgs
			}
		}()

	case layers.ARPReply:

		//===================================
		// HANDLE REPLIES TO OUR ARP REQUESTS
		//===================================

		var srcIp *Ip
		var srcMac *Mac
		if aa := cfg.arp.active.Get(sAddrs.SenIp); aa != nil {
			if aa.Cancel != nil {
				aa.Cancel()
			}
			if srcMac, srcIp, _, err = sAddrs.getOrCreateSnifferDbValues(cfg, ActiveArpMeth); err == nil {
				cfg.log.Info("received active arp reply", zap.String("ip", srcIp.Value),
					zap.String("mac", srcMac.Value), zap.String("replyType", "active"))
			}
		} else {
			if srcMac, srcIp, _, err = sAddrs.getOrCreateSnifferDbValues(cfg, PassiveArpMeth); err == nil {
				cfg.log.Info("received passive arp reply", zap.String("ip", srcIp.Value),
					zap.String("mac", srcMac.Value), zap.String("replyType", "passive"))
			}
		}

		if err != nil {
			cfg.log.Error("failed to handle arp reply", zap.Error(err))
			return err
		}
	}

	return
}

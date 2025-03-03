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
	"slices"
	"time"
)

const (
	maxArpRetries = 3
	arpTimeout    = 8 * time.Second
)

var (
	anyAddr = make([]byte, 4)
)

type (
	// ActiveArp represents an ARP request.
	ActiveArp struct {
		TarIp  *Ip
		ctx    context.Context
		cancel context.CancelFunc
	}

	// arpStringAddrs consists of network addresses in string format that
	// were extracted from an ARP packet.
	arpStringAddrs struct {
		SenIp, SenHw, TarIp, TarHw string
	}

	// SendArpCfg represent values needed to send an ARP request/response.
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
	}

	// ArpSpoofHandler defines the signature for functions that handle
	// packets that are received after poisoning a sender's ARP table.
	ArpSpoofHandler func(packet gopacket.Packet)

	// AttackSnacCfg is used to configure an ARP spoofing attack.
	AttackSnacCfg struct {
		// Calling the cancel func associated with Ctx stops the
		// ARP spoofing attack.
		Ctx      context.Context
		SenderIp net.IP
		TargetIp net.IP
		// Handlers are functions that each packet is passed to.
		Handlers []ArpSpoofHandler
	}

	// doArpRequestArgs enables documentation of arguments.
	doArpRequestArgs[AT ActiveArp] struct {
		tarIpRecord *Ip          // current ip db record being resolved for
		senIp       []byte       // sender ip address
		senHw       []byte       // sender hw address
		tarIp       []byte       // target ip address
		tarHw       []byte       // target hardware address
		handle      *pcap.Handle // handle used to write the arp packet to the wire
	}
)

// newUnpackedArp converts binary address values to string.
func newUnpackedArp(arp *layers.ARP) arpStringAddrs {
	return arpStringAddrs{
		SenIp: net.IP(arp.SourceProtAddress).String(),
		SenHw: net.HardwareAddr(arp.SourceHwAddress).String(),
		TarIp: net.IP(arp.DstProtAddress).String(),
		TarHw: net.HardwareAddr(arp.DstHwAddress).String(),
	}
}

// SendArp sends an ARP request described by SendArpCfg.
func SendArp(cfg Cfg, sA SendArpCfg) error {
	// SOURCE: https://github.com/google/gopacket/blob/master/examples/arpscan/arpscan.go

	if sA.TargetHw == nil {
		if sA.Operation == layers.ARPReply {
			return errors.New("sending arp replies require a TargetHw value")
		}
		sA.TargetHw = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	}

	eth := layers.Ethernet{
		SrcMAC:       sA.SenderHw,
		DstMAC:       sA.TargetHw,
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
		DstHwAddress:      sA.TargetHw,
		DstProtAddress:    sA.TargetIp.To4(),
	}
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	buff := gopacket.NewSerializeBuffer()
	err := gopacket.SerializeLayers(buff, opts, &eth, &arp)
	cfg.log.Debug("sending arp packet",
		zap.String("senderIp", sA.SenderIp.String()), zap.String("senderMac", sA.SenderHw.String()),
		zap.String("targetIp", sA.TargetIp.String()), zap.String("targetMac", sA.TargetHw.String()),
	)
	if err != nil {
		cfg.log.Error("error serializing packet", zap.Error(err))
		return fmt.Errorf("failed to build arp packet: %w", err)
	} else if err = sA.Handle.WritePacketData(buff.Bytes()); err != nil {
		cfg.log.Error("error writing packet data", zap.Error(err),
			zap.String("senderIp", sA.SenderIp.String()), zap.String("senderMac", sA.SenderHw.String()),
			zap.String("targetIp", sA.TargetIp.String()), zap.String("targetMac", sA.TargetHw.String()),
		)
		return fmt.Errorf("failed to send arp packet: %w", err)
	}

	return nil
}

// doArpRequest configures and sends an ARP request.
func doArpRequest(cfg Cfg, args doArpRequestArgs[ActiveArp], maxRetries int) {

	cfg.log.Info("initiating arp request", zap.String("ip", args.tarIpRecord.Value))

	ctx, cancel := context.WithTimeout(context.Background(), arpTimeout)
	context.AfterFunc(ctx, func() {
		cancel()
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			if maxRetries > 0 {
				go doArpRequest(cfg, args, maxRetries-1)
				cfg.log.Info("retrying arp request",
					zap.String("targetIp", args.tarIpRecord.Value),
					zap.Int("remainingRetries", maxRetries))
				return
			}
			cfg.log.Info("never received arp response", zap.String("targetIp", args.tarIpRecord.Value))
		}
		if err := SetArpResolved(cfg.db, args.tarIpRecord.Id); err != nil {
			cfg.log.Error("failed to set arp as resolved for ip", zap.String("targetIp", args.tarIpRecord.Value))
		}
		cfg.activeArps.Delete(args.tarIpRecord.Value)
	})

	cfg.activeArps.Set(args.tarIpRecord.Value, &ActiveArp{TarIp: args.tarIpRecord, ctx: ctx, cancel: cancel})

	cfg.arpSenderC <- SendArpCfg{
		Operation: layers.ARPRequest,
		Handle:    args.handle,
		SenderHw:  args.senHw,
		SenderIp:  args.senIp,
		TargetIp:  args.tarIp,
		TargetHw:  args.tarHw,
	}
}

func handlePacket(cfg Cfg, handle *pcap.Handle, packet gopacket.Packet, requestedArps *[]string) (err error) {

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

		if tarIp.MacId == nil && !tarIp.ArpResolved &&
		  !slices.Contains(*requestedArps, tarIp.Value) && cfg.activeArps.Get(tarIp.Value) == nil {

			*requestedArps = append(*requestedArps, tarIp.Value)

			//============================
			// SEND ARP REQUEST FOR TARGET
			//============================

			go doArpRequest(cfg, doArpRequestArgs[ActiveArp]{
				tarIpRecord: tarIp,
				senIp:       cfg.ipNet.IP.To4(),
				senHw:       cfg.iface.HardwareAddr,
				tarIp:       arpL.DstProtAddress,
				tarHw:       nil,
				handle:      handle,
			}, 5)

		}

		//===================
		// DO NAME RESOLUTION
		//===================

		// skip name resolution AfterF excess failures
		if dnsFailCounter.Exceeded() {
			return
		}

		// determine which ips to reverse resolve
		var toResolve []*Ip
		for _, ip := range []*Ip{senIp, tarIp} {
			if !ip.PtrResolved && cfg.activeDns.Get(FmtDnsKey(ip.Value, PtrDnsKind)) == nil {
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
					SenderC: cfg.dnsSenderC,
					Kind:    PtrDnsKind,
					Target:  ip.Value,
					FailureF: func(e error) {
						if err := SetPtrResolved(cfg.db, *ip); err != nil {
							cfg.activeDns.Delete(FmtDnsKey(ip.Value, PtrDnsKind))
							cfg.log.Error("failed to set ptr to resolved", zap.String("ip", ip.Value), zap.Error(err))
							return
						}
						cfg.activeDns.Delete(FmtDnsKey(ip.Value, PtrDnsKind))
					},
					AfterF: func(names []string) {
						if err := SetPtrResolved(cfg.db, *ip); err != nil {
							cfg.activeDns.Delete(FmtDnsKey(ip.Value, PtrDnsKind))
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
						cfg.activeDns.Delete(FmtDnsKey(ip.Value, PtrDnsKind))
					},
				}
				cfg.activeDns.Set(FmtDnsKey(ip.Value, PtrDnsKind), &dArgs)
				cfg.dnsSenderC <- dArgs
			}
		}()

	case layers.ARPReply:

		//===================================
		// HANDLE REPLIES TO OUR ARP REQUESTS
		//===================================

		var srcIp *Ip
		var srcMac *Mac
		if aa := cfg.activeArps.Get(sAddrs.SenIp); aa != nil {
			aa.cancel()
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

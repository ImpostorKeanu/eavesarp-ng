package eavesarp_ng

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"io"
	"net"
)

var (
	NoTransportLayerErr = errors.New("no transport layer found")
)

// getInterface gets the network interface described by name and addr.
//
// addr is optional (can be empty) and is used to specify which address
// to listen for when multiple IPv4 addresses are assigned to the interface.
func getInterface(name string, addr string, eWriters *EventWriters) (iface *net.Interface, ipnet *net.IPNet, err error) {

	var iAddr net.IP
	if addr != "" {
		if iAddr = net.ParseIP(addr); iAddr == nil {
			err = errors.New("invalid addr")
			return
		}
	}

	iface, err = net.InterfaceByName(name)
	if err != nil {
		eWriters.Writef("error looking up network interface: %v", err.Error())
		return
	}

	var addrs []net.Addr
	addrs, err = iface.Addrs()
	if err != nil {
		eWriters.Writef("failed to obtain ip address from network interface: %v", err.Error())
		return
	} else {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() {
				if ip4 := n.IP.To4(); ip4 != nil {
					if addr != "" && ip4.String() != addr {
						continue
					}
					ipnet = &net.IPNet{
						IP:   ip4,
						Mask: n.Mask[len(n.Mask)-4:],
					}
				}
			}
		}
	}

	if ipnet == nil {
		err = fmt.Errorf("failed to find network interface %v", name)
		if addr != "" {
			err = fmt.Errorf("%v with ip address %v", err, addr)
		}
	}

	return
}

// MainSniff starts the ARP and DNS background routines and sniffs network traffic
// from the interface until the context is done.
//
// - iName is the name of the network interface to sniff on.
// - iAddr optionally (empty string) specifies the ipv4 address
//    on the interface to sniff for.
// - When snacSniffCh receives ArpSpoofCfg, a new background routine
//   to perform an ARP spoofing attack is started.
func MainSniff(ctx context.Context, db *sql.DB, iName, iAddr string, arpSpoofCh chan ArpSpoofCfg,
  eventWriters ...io.StringWriter) (err error) {
	// SOURCE: https://github.com/google/gopacket/blob/master/examples/arpscan/arpscan.go

	eWriters := NewEventWriters(eventWriters...)

	arpSleeper := NewSleeper(1, 5, 30)
	dnsSleeper := NewSleeper(1, 5, 30)

	ch := make(chan error) // channel to receive notification of death
	dnsSenderC := make(chan DoDnsCfg, 50)
	arpSenderC := make(chan SendArpCfg, 50)

	// create child contexts for each subroutine
	sniffCtx, sniffCancel := context.WithCancel(ctx)
	snacSniffCtx, snacSniffCancel := context.WithCancel(ctx)
	arpSenderCtx, arpSenderCancel := context.WithCancel(ctx)
	dnsSenderCtx, dnsSenderCancel := context.WithCancel(ctx)

	go func() {
		dieCh := make(chan error) // to listen for routine death
		//defer close(dieCh)

		// start snac sniff routine
		go func() {
			for {
				select {
				case <-snacSniffCtx.Done():
					return
				case args := <-arpSpoofCh:

					// start routine that waits for sniff job to finish
					go func() {
						// start sniff job
						ctx, cancel := context.WithCancel(args.Ctx)
						go func() {
							err := ArpSpoof(ctx, iName, iAddr, arpSenderC,
								args.SenderIp, args.TargetIp, eWriters, args.Handlers...)
							if err != nil {
								dieCh <- err
							}
						}()

						// wait for sniff job to finish
						select {
						case <-snacSniffCtx.Done():
							cancel()
						case <-args.Ctx.Done():
							cancel()
						}

					}()
				}
			}
		}()

		// start arp sender
		go func() {
			dieCh <- SenderServer(arpSenderCtx, arpSleeper, arpSenderC, SendArp)
		}()

		// start dns sender
		go func() {
			dieCh <- SenderServer(dnsSenderCtx, dnsSleeper, dnsSenderC, SendDns)
		}()

		// start main sniffer
		go func() {
			dieCh <- WatchArp(sniffCtx, db, iName, iAddr, arpSenderC, dnsSenderC, eventWriters...)
		}()

		err := <-dieCh // block until an error or nil is received

		// call all cancel functions
		sniffCancel()
		arpSenderCancel()
		dnsSenderCancel()
		snacSniffCancel()

		close(arpSenderC)
		close(dnsSenderC)

		ch <- err // notify main routine
	}()

	err = <-ch // wait for completion
	close(ch)

	return
}

// WatchArp is the primary function that monitors ARP requests and initiates DNS name
// resolution for newly discovered IP addresses.
func WatchArp(ctx context.Context, db *sql.DB, iName, iAddr string,
  arpSenderC chan SendArpCfg, dnsSenderC chan DoDnsCfg, eventWriters ...io.StringWriter) (err error) {

	eWriters := EventWriters{writers: eventWriters}
	activeArps := NewLockMap(make(map[string]*ActiveArp)) // track arp requests
	activeDns := NewLockMap(make(map[string]*DoDnsCfg))   // track dns requests

	//==========================
	// PREPARE NETWORK INTERFACE
	//==========================

	iface, ifaceAddr, err := getInterface(iName, iAddr, &eWriters)
	if err != nil {
		eWriters.Writef("failed to obtain interface: %s", err.Error())
		return err
	}

	//============================
	// PERPETUALLY CAPTURE PACKETS
	//============================

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		eWriters.Writef("error opening packet capture: %v", err.Error())
		return err
	}
	defer handle.Close()
	if err = handle.SetBPFFilter("arp"); err != nil {
		eWriters.Writef("failed to set bpf filter: %v", err.Error())
		return err
	}

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()

outer:
	for {
		var packet gopacket.Packet
		select {
		case <-ctx.Done():
			eWriters.Write("killing sniff routine")
			return
		case packet = <-in:
			arpL := GetArpLayer(packet)
			if arpL == nil {
				continue outer
			}
			sAddrs := newUnpackedArp(arpL)

			switch arpL.Operation {
			case layers.ARPRequest:

				//======================================
				// HANDLE PASSIVELY CAPTURED ARP REQUEST
				//======================================

				if bytes.Equal(iface.HardwareAddr, arpL.SourceHwAddress) {
					// ignore arp requests from our nic
					continue outer
				} else if ifaceAddr.IP.Equal(arpL.DstProtAddress) {
					// capture ARP requests for senders wanting our mac address
					if _, srcIp, e := sAddrs.getOrCreateSourceDbValues(db, PassiveArpMeth, &eWriters); e != nil {
						err = e
						return
					} else if srcIp.IsNew {
						eWriters.Writef("new ip requested our mac: %v", srcIp.Value)
					}
					continue outer
				}

				_, senIp, tarIp, err := sAddrs.getOrCreateSnifferDbValues(db, PassiveArpMeth, &eWriters)

				if senIp.IsNew {
					eWriters.Writef("new sender ip passively discovered: %v", senIp.Value)
				}
				if tarIp.IsNew {
					eWriters.Writef("new target ip passively discovered: %v", tarIp.Value)
				}

				//====================
				// INCREMENT ARP COUNT
				//====================

				_, err = IncArpCount(db, senIp.Id, tarIp.Id)
				if err != nil {
					eWriters.Writef("failed to increment arp count: %v", err.Error())
					continue outer
				}

				if tarIp.MacId == nil && activeArps.Get(tarIp.Value) == nil && !tarIp.ArpResolved {

					//============================
					// SEND ARP REQUEST FOR TARGET
					//============================

					//go doArpRequest(db, tarIp, ifaceAddr.IP.To4(), iface.HardwareAddr, arpL.DstProtAddress, nil,
					//	handle, arpSenderC, activeArps, &eWriters)
					go doArpRequest(db, doArpRequestArgs[ActiveArp]{
						tarIpRecord: tarIp,
						senIp:       ifaceAddr.IP.To4(),
						senHw:       iface.HardwareAddr,
						tarIp:       arpL.DstProtAddress,
						tarHw:       nil,
						senderC:     arpSenderC,
						activeArps:  activeArps,
						handle:      handle,
					}, &eWriters)

				}

				//===================
				// DO NAME RESOLUTION
				//===================

				// skip name resolution AfterF excess failures
				if dnsFailCounter.Exceeded() {
					continue outer
				}

				// determine which ips to reverse resolve
				var toResolve []*Ip
				for _, ip := range []*Ip{senIp, tarIp} {
					if !ip.PtrResolved && activeDns.Get(FmtDnsKey(ip.Value, PtrDnsKind)) == nil {
						toResolve = append(toResolve, ip)
					}
				}

				if len(toResolve) == 0 {
					continue outer
				}

				// reverse resolve each ip
				go func() {
					for _, ip := range toResolve {
						dArgs := DoDnsCfg{
							SenderC: dnsSenderC,
							Kind:    PtrDnsKind,
							Target:  ip.Value,
							FailureF: func(e error) {
								if err := SetPtrResolved(db, *ip); err != nil {
									activeDns.Delete(FmtDnsKey(ip.Value, PtrDnsKind))
									eWriters.Writef("failed to set ptr to resolved: %v", err.Error())
									return
								}
								activeDns.Delete(FmtDnsKey(ip.Value, PtrDnsKind))
							},
							AfterF: func(names []string) {
								if err := SetPtrResolved(db, *ip); err != nil {
									activeDns.Delete(FmtDnsKey(ip.Value, PtrDnsKind))
									eWriters.Writef("failed to set ptr to resolved: %v", err.Error())
									return
								}
								for _, name := range names {
									handlePtrName(db, 10, handlePtrNameArgs[DoDnsCfg, ActiveArp]{
										ip:         ip,
										name:       name,
										srcIfaceIp: ifaceAddr.IP.To4(),
										srcIfaceHw: iface.HardwareAddr,
										activeArp:  activeArps,
										arpSenderC: arpSenderC,
										activeDns:  activeDns,
										dnsSenderC: dnsSenderC,
										handle:     handle,
									}, &eWriters)
								}
								activeDns.Delete(FmtDnsKey(ip.Value, PtrDnsKind))
							},
						}
						activeDns.Set(FmtDnsKey(ip.Value, PtrDnsKind), &dArgs)
						dnsSenderC <- dArgs
					}
				}()

			case layers.ARPReply:

				//===================================
				// HANDLE REPLIES TO OUR ARP REQUESTS
				//===================================

				if aa := activeArps.Get(sAddrs.SenIp); aa != nil {
					aa.cancel()
					var srcIp *Ip
					var srcMac *Mac
					srcMac, srcIp, _, err = sAddrs.getOrCreateSnifferDbValues(db, ActiveArpMeth, &eWriters)
					if err != nil {
						eWriters.Writef("failed to Handle arp reply: %v", err.Error())
						return err
					}
					eWriters.Writef("received arp reply: %s (%s)", srcIp.Value, srcMac.Value)
				}
			}
		}
	}
}

func (u arpStringAddrs) getOrCreateSourceDbValues(db *sql.DB, arpMethod DiscMethod, eWriters *EventWriters) (srcMac *Mac, srcIp *Ip, err error) {

	//===========
	// HANDLE SRC
	//===========

	// MAC
	srcMacBuff, err := GetOrCreateMac(db, u.SenHw, arpMethod)
	if err != nil {
		eWriters.Writef("failed to create mac: %v", err.Error())
		return
	}
	srcMac = &srcMacBuff

	// IP
	srcIpBuff, err := GetOrCreateIp(db, u.SenIp, &srcMacBuff.Id, arpMethod, true, false)
	if err != nil {
		eWriters.Writef("failed to create mac: %v", err.Error())
		return
	} else if srcIpBuff.MacId == nil {

		//============
		// SET SRC MAC
		//============
		// - the mac is unavailable when a _target_ IP address was discovered via ARP request
		// - since goc doesn't update records, we'll need to update it manually

		if _, err = db.Exec(`UPDATE ip SET mac_id=? WHERE id=?`, srcMac.Id, srcIpBuff.Id); err != nil {
			eWriters.Writef("failed to update ip with mac address: %v", err.Error())
			return
		}
		srcIpBuff.MacId = &srcMac.Id
	}
	srcIp = &srcIpBuff

	return
}

func (u arpStringAddrs) getOrCreateSnifferDbValues(db *sql.DB, arpMethod DiscMethod, eWriters *EventWriters) (srcMac *Mac, srcIp *Ip,
  dstIp *Ip, err error) {

	if srcMac, srcIp, err = u.getOrCreateSourceDbValues(db, arpMethod, eWriters); err != nil {
		return
	}

	if arpMethod == PassiveArpMeth {
		var dstIpBuff Ip
		dstIpBuff, err = GetOrCreateIp(db, u.TarIp, nil, arpMethod, false, false)
		if err != nil {
			eWriters.Writef("failed to create mac: %v", err.Error())
			return
		}
		dstIp = &dstIpBuff
	}

	return
}

// GetPacketTransportLayerInfo extracts the transport layer protocol and port from
// a packet.
//
// An error is returned if an unknown transport layer is found. When this occurs,
// proto and dstPort are zero values.
//
// Known protocols transport layer protocols: `tcp`, `udp`, `sctp`
func GetPacketTransportLayerInfo(packet gopacket.Packet, eWriters *EventWriters) (proto string, dstPort int, err error) {
	transLayer := packet.TransportLayer()
	if transLayer == nil {
		err = NoTransportLayerErr
		return
	}
	switch lT := transLayer.LayerType(); lT {
	case layers.LayerTypeTCP:
		layer := transLayer.(*layers.TCP)
		proto = "tcp"
		dstPort = int(layer.DstPort)
	case layers.LayerTypeUDP:
		layer := transLayer.(*layers.UDP)
		proto = "udp"
		dstPort = int(layer.DstPort)
	case layers.LayerTypeSCTP:
		layer := transLayer.(*layers.SCTP)
		proto = "sctp"
		dstPort = int(layer.DstPort)
	default:
		err = errors.New("unknown transport layer type captured")
		eWriters.Write(err.Error())
	}
	return
}

// GetArpLayer extracts the ARP layer from packet, returning nil when no
// ARP layer is found.
func GetArpLayer(packet gopacket.Packet) *layers.ARP {
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		return arpLayer.(*layers.ARP)
	}
	return nil
}

// ArpSpoof poisons the sender's ARP table by sending our MAC address
// when a request for the target's IP is observed. After poisoning
// occurs and non-ARP traffic is detected, each packet is passed to
// a series of handler functions.
//
// NOTE: Before poisoning the sender's ARP table, this function passively
// waits for the sender to broadcast an ARP request.
func ArpSpoof(ctx context.Context, iName, iAddr string, arpSenderC chan SendArpCfg, senIp net.IP, tarIp net.IP,
  eWriters *EventWriters, handlers ...ArpSpoofHandler) (err error) {

	iface, _, err := getInterface(iName, iAddr, eWriters)
	if err != nil {
		eWriters.Writef("failed to retrive interface and addr: %v", err.Error())
		return
	}

	var handle *pcap.Handle
	handle, err = pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		eWriters.Writef("failed to start packet capture: %v", err.Error())
		return
	}
	defer handle.Close()

	if err = handle.SetBPFFilter(fmt.Sprintf("src host %s && dst host %s", senIp.String(), tarIp.String())); err != nil {
		eWriters.Writef("failed to set bpf filter: %v", err.Error())
		return
	}

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-in:

			if arp := GetArpLayer(packet); arp != nil && arp.Operation == layers.ARPRequest {
				// Respond with our MAC
				arpSenderC <- SendArpCfg{
					Handle:    handle,
					Operation: layers.ARPReply,
					SenderHw:  iface.HardwareAddr,
					SenderIp:  tarIp,
					TargetHw:  arp.SourceHwAddress,
					TargetIp:  arp.SourceProtAddress,
				}
				continue
			}

			// Run handlers
			go func() {
				for _, h := range handlers {
					if h != nil {
						h(packet)
					}
				}
			}()
		}
	}
}

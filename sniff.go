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

type (
	SnacSniffHandler func(packet gopacket.Packet)
)

var (
	stopSnifferC        = make(chan bool)
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

// MainSniff starts sniffer subprocesses.
//
// - iName is the name of the network interface to sniff on.
// - iAddr optionally (empty string) specifies the ipv4 address
//    on the interface to sniff for.
func MainSniff(db *sql.DB, iName, iAddr string, eventWriters ...io.StringWriter) (err error) {
	// SOURCE: https://github.com/google/gopacket/blob/master/examples/arpscan/arpscan.go

	eWriters := EventWriters{writers: eventWriters}

	//==========================
	// START BACKGROUND ROUTINES
	//==========================

	go ArpSender(&eWriters)
	defer func() {
		eWriters.Write("killing arp sender routine")
		stopArpSenderC <- true
	}()

	go DnsSender(&eWriters)
	defer func() {
		eWriters.Write("killing dns sender routine")
		stopDnsSenderC <- true
	}()

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
		case <-stopSnifferC:
			break outer
		case packet = <-in:

			arpL := GetArpLayer(packet)
			if arpL == nil {
				continue
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

				if tarIp.MacId == nil && !activeArps.Has(tarIp.Value) && !tarIp.ArpResolved {

					//=================
					// SEND ARP REQUEST
					//=================

					arpSenderC <- ArpSenderArgs{
						operation: layers.ARPRequest,
						handle:    handle,
						srcHw:     iface.HardwareAddr,
						srcIp:     ifaceAddr.IP,
						dstIp:     arpL.DstProtAddress,
						addActiveArp: func() (err error) {
							err = activeArps.Add(tarIp, &eWriters, func() error { return SetArpResolved(db, tarIp.Id) })
							if err != nil && !errors.Is(err, activeArpAlreadySet) {
								eWriters.Writef("error: failed to watch for active arp response: %v", err.Error())
								return
							} else if err != nil {
								// TODO
								eWriters.Writef("error: unhandled exception: %v", err.Error())
								err = nil
							}
							return
						},
					}

					eWriters.Writef("initiated active arp request for %v", tarIp.Value)
				}

				//====================
				// INCREMENT ARP COUNT
				//====================

				_, err = IncArpCount(db, senIp.Id, tarIp.Id)
				if err != nil {
					eWriters.Writef("failed to increment arp count: %v", err.Error())
					continue
				}

				//===================
				// DO NAME RESOLUTION
				//===================

				if !dnsFailCounter.Exceeded() {
					for _, ip := range []*Ip{senIp, tarIp} {
						if !ip.PtrResolved {
							dnsSenderC <- DnsSenderArgs{
								kind:   PtrDnsKind,
								target: ip.Value,
								failure: func(e error) {
									if err := SetPtrResolved(db, *ip); err != nil {
										eWriters.Writef("failed to set ptr to resolved: %v", err.Error())
										return
									}
								},
								after: func(names []string) {
									if err := SetPtrResolved(db, *ip); err != nil {
										eWriters.Writef("failed to set ptr to resolved: %v", err.Error())
										return
									}
									for _, name := range names {
										handlePtrName(db, &eWriters, ip, name, nil)
									}
								},
							}
						}
					}
				}

			case layers.ARPReply:

				//===================
				// HANDLE ARP REPLIES
				//===================

				if activeArpIp := activeArps.Get(sAddrs.SenIp); activeArpIp != nil {
					var srcIp *Ip
					var srcMac *Mac
					srcMac, srcIp, _, err = sAddrs.getOrCreateSnifferDbValues(db, ActiveArpMeth, &eWriters)
					if err != nil {
						eWriters.Writef("failed to handle arp reply: %v", err.Error())
						return err
					}
					eWriters.Writef("received arp reply: %s (%s)", srcIp.Value, srcMac.Value)
				}
			}
		}
	}

	eWriters.Write("exiting main sniffer thread")
	return
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

func GetArpLayer(packet gopacket.Packet) *layers.ARP {
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		return arpLayer.(*layers.ARP)
	}
	return nil
}

// SnacSniffWriter should be run as a background process to receive
// packets that are written to a pcap file.
func SnacSniffWriter(ctx context.Context, c chan []byte, fileName string) (err error) {
	var handle *pcap.Handle
	if handle, err = pcap.OpenOffline(fileName); err != nil {
		return err
	}
	defer handle.Close()
outer:
	for {
		select {
		case <-ctx.Done():
			// TODO handle
			return nil
		case packetData := <-c:
			if err = handle.WritePacketData(packetData); err != nil {
				// TODO handle
				break outer
			}
		}
	}
	return
}

// SnacSniff is used to initiate a standalone packet capture for a
// specific source IP (srcIp) while passing each captured packet to
// a series of handler functions.
func SnacSniff(ctx context.Context, iName, iAddr string, srcIp net.IP, dstIp net.IP, maxPackets int, eWriters *EventWriters,
  handlers ...SnacSniffHandler) (err error) {

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

	if err = handle.SetBPFFilter(fmt.Sprintf("src host %s && dst host %s", srcIp.String(), dstIp.String())); err != nil {
		eWriters.Writef("failed to set bpf filter: %v", err.Error())
		return
	}

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()

	var pCount int

outer:
	for {
		select {
		case <-ctx.Done():
			break outer
		case packet := <-in:

			if arp := GetArpLayer(packet); arp != nil && arp.Operation == layers.ARPRequest {
				// Respond with our MAC
				arpSenderC <- ArpSenderArgs{
					handle:    handle,
					operation: layers.ARPReply,
					srcHw:     iface.HardwareAddr,
					srcIp:     dstIp,
					dstHw:     arp.SourceHwAddress,
					dstIp:     arp.SourceProtAddress,
				}
				continue
			}

			// Run handlers
			go func() {
				for _, h := range handlers {
					h(packet)
				}
			}()

			if maxPackets > 0 {
				if pCount >= maxPackets {
					break outer
				}
				pCount++
			}
		}
	}

	return
}

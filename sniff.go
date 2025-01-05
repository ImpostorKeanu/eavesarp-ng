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
	"net"
	"os"
	"sync"
	"time"
)

var (
	activeArps     = ActiveArps{sync.RWMutex{}, make(map[string]*ActiveArp)}
	arpSenderC     = make(chan ArpSenderArgs)
	stopArpSenderC = make(chan bool)
	stopSnifferC   = make(chan bool)
	stopDnsSenderC = make(chan bool)
	dnsSenderC     = make(chan DnsSenderArgs)
	resolver       = net.Resolver{}

	PtrDnsKind DnsKind = "ptr"
	ADnsKind   DnsKind = "a"

	activeArpAlreadySet = errors.New("already set")
	unsupportedDnsError = errors.New("unsupported dns record type")
)

type (
	// ActiveArp represents an ARP request.
	ActiveArp struct {
		DstIp  *Ip
		ctx    context.Context
		cancel context.CancelFunc
	}

	// ActiveArps map string IPv4 addresses to ActiveArp records.
	//
	// ActiveArp instances are
	ActiveArps struct {
		mu sync.RWMutex
		v  map[string]*ActiveArp
	}

	// unpackedArp consists of network addresses in string format that
	// were extracted from an ARP packet.
	unpackedArp struct {
		SrcIp, SrcHw, DstIp, DstHw string
	}

	// ArpSenderArgs represent values needed to send an ARP request.
	ArpSenderArgs struct {
		handle       *pcap.Handle
		srcIface     *net.Interface
		addr         *net.IPNet
		dstIp        []byte
		addActiveArp func() error
	}

	DnsKind string

	DnsSenderArgs struct {
		kind   DnsKind
		target string
		after  func([]string)
	}
)

// Get the IP for an active arp.
//
// Note: This method has side effects! It removes the requested
//       ip, cancels the context, and removes it from the container.
func (a *ActiveArps) Get(ip string) *Ip {
	a.mu.Lock()
	defer a.mu.Unlock()
	if v, ok := a.v[ip]; ok {
		v.cancel()
		delete(a.v, ip)
		return v.DstIp
	}
	return nil
}

// Has determines if ActiveArps has a job for the ip.
func (a *ActiveArps) Has(ip string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	_, ok := a.v[ip]
	return ok
}

// Add a new active ARP job for the ip.
//
// afterFuncs are executed after the active ARP instance
// times out.
func (a *ActiveArps) Add(i *Ip, afterFuncs ...func() error) (err error) {
	if !a.Has(i.Value) {
		a.mu.Lock()
		defer a.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		context.AfterFunc(ctx, func() {

			for _, f := range afterFuncs {
				if err := f(); err != nil {
					// TODO logging
					println("failed to execute afterfunc", err.Error())
				}
			}

			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				// TODO logging
				fmt.Printf("never received active arp response for %v\n", i.Value)
				cancel()
				a.Del(i.Value)
			}
		})
		a.v[i.Value] = &ActiveArp{DstIp: i, ctx: ctx, cancel: cancel}
		return
	}

	return activeArpAlreadySet
}

// Del removes an active ARP job for the ip.
func (a *ActiveArps) Del(ip string) (v *Ip) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v = a.v[ip].DstIp
	delete(a.v, ip)
	return
}

// newUnpackedArp converts binary address values to string and
// returns an unpackedArp instance.
func newUnpackedArp(arp *layers.ARP) unpackedArp {
	return unpackedArp{
		SrcIp: net.IP(arp.SourceProtAddress).String(),
		SrcHw: net.HardwareAddr(arp.SourceHwAddress).String(),
		DstIp: net.IP(arp.DstProtAddress).String(),
		DstHw: net.HardwareAddr(arp.DstHwAddress).String(),
	}
}

func Sniff(db *sql.DB) {
	// SOURCE: https://github.com/google/gopacket/blob/master/examples/arpscan/arpscan.go

	defer db.Close()
	go ArpSender()
	defer func() {
		// TODO
		println("killing arp sender process")
		stopArpSenderC <- true
	}()

	go DnsSender()
	defer func() {
		// TODO
		println("killing dns sender process")
		stopDnsSenderC <- true
	}()

	//==========================
	// PREPARE NETWORK INTERFACE
	//==========================

	iface, err := net.InterfaceByName("enp13s0")
	if err != nil {
		// TODO
		println("error looking up network interface: ", err.Error())
		os.Exit(1)
	}

	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		// TODO
		println("failed to obtain ip address from network interface: ", err.Error())
		os.Exit(1)
	} else {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() {
				if ip4 := n.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: n.Mask[len(n.Mask)-4:],
					}
				}
			}
		}
	}

	//============================
	// PERPETUALLY CAPTURE PACKETS
	//============================

	println("starting packet capture")

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		// TODO
		println("error opening packet capture: ", err.Error())
		os.Exit(1)
	}

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		var packet gopacket.Packet
		select {
		case <-stopSnifferC:
			return
		case packet = <-in:

			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp := arpLayer.(*layers.ARP)

			// Ignore ARP requests generated by our interface
			// TODO this should probably check all interfaces, not just the one
			//      we're sniffing
			if bytes.Equal(iface.HardwareAddr, arp.SourceHwAddress) {
				continue
			}

			u := newUnpackedArp(arp)

			switch arp.Operation {
			case layers.ARPRequest:

				//======================================
				// HANDLE PASSIVELY CAPTURED ARP REQUEST
				//======================================

				fmt.Printf("ARP Request: %s (%s) -> %s\n", u.SrcIp, u.SrcHw, u.DstIp)

				_, srcIp, dstIp, err := u.GetOrCreateDbValues(db, PassiveArpMeth)

				if dstIp.MacId == nil && !activeArps.Has(dstIp.Value) && !dstIp.ArpResolved {

					//=================
					// SEND ARP REQUEST
					//=================

					// Initiate ARP request
					arpSenderC <- ArpSenderArgs{
						handle:   handle,
						srcIface: iface,
						addr:     addr,
						dstIp:    arp.DstProtAddress,
						addActiveArp: func() (err error) {
							err = activeArps.Add(dstIp, func() error { return SetArpResolved(db, dstIp.Id) })
							if err != nil && !errors.Is(err, activeArpAlreadySet) {
								// TODO logging
								println("failed to watch for active arp response", err.Error())
								os.Exit(1)
							} else if err != nil {
								err = nil
							}
							return
						},
					}

					fmt.Printf("initiated active arp request for %v\n", dstIp.Value)
				}

				//===================
				// DO NAME RESOLUTION
				//===================

				for _, ip := range []*Ip{srcIp, dstIp} {
					if !ip.PtrResolved {
						dnsSenderC <- DnsSenderArgs{
							kind:   PtrDnsKind,
							target: ip.Value,
							after: func(names []string) {
								for _, name := range names {
									ptrCallback(db, ip, name, nil)
								}
							},
						}
					}
				}

				//====================
				// INCREMENT ARP COUNT
				//====================

				count, err := IncArpCount(db, srcIp.Id, dstIp.Id)
				if err != nil {
					// TODO
					println("failed to increment arp count: ", err.Error())
					os.Exit(1)
				}
				fmt.Printf("Incremented arp count: %s -> %s -> %d\n", srcIp.Value, dstIp.Value, count)

			case layers.ARPReply:

				//===================
				// HANDLE ARP REPLIES
				//===================

				fmt.Printf("ARP Response: %s (%s) -> %s (%s)\n", u.SrcIp, u.SrcHw, u.DstIp, u.DstHw)

				if ip := activeArps.Get(u.SrcIp); ip != nil {
					srcMac, srcIp, _, err := u.GetOrCreateDbValues(db, ActiveArpMeth)
					if err != nil {
						// TODO
						println("failed to handle arp reply: ", err.Error())
						os.Exit(1)
					}
					fmt.Printf("received arp reply: %s (%s)\n", srcIp.Value, srcMac.Value)
				}
			}
		}
	}
}

func (u unpackedArp) GetOrCreateDbValues(db *sql.DB, arpMethod DiscMethod) (srcMac *Mac, srcIp *Ip,
  dstIp *Ip, err error) {

	// goc src mac
	srcMacBuff, err := GetOrCreateMac(db, u.SrcHw, arpMethod)
	if err != nil {
		// TODO
		println("failed to create mac: ", err.Error())
		os.Exit(1)
	}
	srcMac = &srcMacBuff

	// goc src ip
	srcIpBuff, err := GetOrCreateIp(db, u.SrcIp, &srcMacBuff.Id, arpMethod, true, false)
	if err != nil {
		// TODO
		println("failed to create mac: ", err.Error())
		os.Exit(1)
	} else if srcIpBuff.MacId == nil {
		if _, err = db.Exec(`UPDATE ip SET mac_id=? WHERE id=?`, srcMac.Id, srcIpBuff.Id); err != nil {
			println("failed to update ip with mac address: ", err.Error())
			os.Exit(1)
		}
		srcIpBuff.MacId = &srcMac.Id
	}
	srcIp = &srcIpBuff

	if arpMethod == PassiveArpMeth {
		// goc dst ip
		dstIpBuff, err := GetOrCreateIp(db, u.DstIp, nil, arpMethod, false, false)
		if err != nil {
			// TODO
			println("failed to create mac: ", err.Error())
			os.Exit(1)
		}
		dstIp = &dstIpBuff
	}

	return
}

func DnsSender() {
	println("starting dns sender process")
	for {
		select {
		case <-stopDnsSenderC:
			println("stopping dns sender process")
			break
		case dA := <-dnsSenderC:

			var err error
			var resolved []string

			// Do resolution
			ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
			switch dA.kind {
			case PtrDnsKind:
				resolved, err = resolver.LookupAddr(ctx, dA.target)
			case ADnsKind:
				resolved, err = resolver.LookupHost(ctx, dA.target)
			default:
				err = unsupportedDnsError
			}
			cancel()

			// TODO handle name resolution error
			if err != nil {
				println("unsupported dns type specified")
				os.Exit(1)
				continue
			}

			// Handle the output
			dA.after(resolved)

		}
	}
}

func ptrCallback(db *sql.DB, ip *Ip, name string, depth *int) {

	if depth == nil {
		buff := 10
		depth = &buff
	}

	dnsName, err := GetOrCreateDnsName(db, name)
	if err != nil {
		// TODO
		println("failed to create dns name", err.Error())
		os.Exit(1)
	}

	if _, err = GetOrCreateDnsPtrRecord(db, *ip, dnsName); err != nil {
		// TODO
		println("failed to create dns ptr record", err.Error())
		os.Exit(1)
	}

	// Do forward lookups for each newly discovered name
	dnsSenderC <- DnsSenderArgs{
		kind:   ADnsKind,
		target: name,
		after: func(newIpStrings []string) {
			for _, newIpS := range newIpStrings {

				newIp, err := GetOrCreateIp(db, newIpS, nil, ForwardDnsMeth,
					false, false)

				if err != nil {
					// TODO
					println("failed to create new ip", err.Error())
					os.Exit(1)
				}

				if _, err = GetOrCreateDnsARecord(db, newIp, dnsName); err != nil {
					// TODO
					println("failed to create dns a record", err.Error())
					os.Exit(1)
				}

				if *depth > 0 && !newIp.PtrResolved {

					dnsSenderC <- DnsSenderArgs{
						kind:   PtrDnsKind,
						target: newIp.Value,
						after: func(names []string) {
							for _, name := range names {
								d := *depth - 1
								ptrCallback(db, ip, name, &d)
							}
						},
					}

				}
			}
		},
	}
}

func ArpSender() {
	// TODO
	println("starting arp sender process")
	for {
		// TODO implement jitter logic here
		// SOURCE: https://github.com/google/gopacket/blob/master/examples/arpscan/arpscan.go
		select {
		case <-stopArpSenderC:
			break
		case sA := <-arpSenderC:

			//========================
			// CONSTRUCT AN ARP PACKET
			//========================

			eth := layers.Ethernet{
				SrcMAC:       sA.srcIface.HardwareAddr,
				DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				EthernetType: layers.EthernetTypeARP,
			}
			arp := layers.ARP{
				AddrType:          layers.LinkTypeEthernet,
				Protocol:          layers.EthernetTypeIPv4,
				HwAddressSize:     6,
				ProtAddressSize:   4,
				Operation:         layers.ARPRequest,
				SourceHwAddress:   []byte(sA.srcIface.HardwareAddr),
				SourceProtAddress: []byte(sA.addr.IP),
				DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
				DstProtAddress:    sA.dstIp,
			}
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}

			var err error
			if err = gopacket.SerializeLayers(buf, opts, &eth, &arp); err != nil {
				// TODO logging
				println("failed to serialize arp packet", err.Error())
				os.Exit(1)
			}

			//=====================
			// SEND THE ARP REQUEST
			//=====================

			// Add an active ARP record _before_ sending the request to
			// avoid a race condition
			if err := sA.addActiveArp(); err != nil {
				// TODO logging
				println("failed to add active arp", err.Error())
				os.Exit(1)
			}

			// Write the ARP request to the wire
			if err := sA.handle.WritePacketData(buf.Bytes()); err != nil {
				// TODO
				println("failed to send arp request", err.Error())
				os.Exit(1)
			}
		}
	}
}

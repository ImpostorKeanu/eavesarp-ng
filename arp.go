package eavesarp_ng

import (
	"context"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"sync"
)

var (
	// activeArps tracks active ARP requests initiated by the application.
	//activeArps = ActiveArps{sync.RWMutex{}, make(map[string]*ActiveArp)}
	activeArps = NewLockMap(make(map[string]*ActiveArp))
	// arpSenderC is used to send ARP requests to a bacground routine.
	arpSenderC = make(chan ArpSenderArgs)
	// stopArpSenderC is used to stop the ArpSender routine.
	stopArpSenderC           = make(chan bool)
	activeArpAlreadySetError = errors.New("already set")
	arpSleeper               = NewSleeper(1, 5, 30)
)

type (
	// ActiveArp represents an ARP request.
	ActiveArp struct {
		TarIp  *Ip
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

	// arpStringAddrs consists of network addresses in string format that
	// were extracted from an ARP packet.
	arpStringAddrs struct {
		SenIp, SenHw, TarIp, TarHw string
	}

	// ArpSenderArgs represent values needed to send an ARP request.
	ArpSenderArgs struct {
		handle    *pcap.Handle
		operation uint64
		srcHw     net.HardwareAddr
		srcIp     net.IP
		dstHw     net.HardwareAddr
		dstIp     net.IP
		// addActiveArp allows the caller to define a function that
		// adds the request to activeArps, which is used to monitor for
		// expected ARP responses.
		//
		// The function should call ActiveArps.Add, the afterFuncs argument
		// for which should have a function that calls SetArpResolved.
		//
		// We do this to avoid database queries in ArpSender.
		//addActiveArp func() error
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

// ArpSender runs as a background process and sends ARP traffic.
func ArpSender(eWriters *EventWriters) {

	eWriters.Write("starting arp sender routine")
	for {
		// SOURCE: https://github.com/google/gopacket/blob/master/examples/arpscan/arpscan.go
		arpSleeper.Sleep()
		select {
		case <-stopArpSenderC:
			break
		case sA := <-arpSenderC:

			if sA.dstHw == nil {
				if sA.operation == layers.ARPReply {
					eWriters.Write("arp replies require a dstHw value")
					continue
				}
				sA.dstHw = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
			}

			eth := layers.Ethernet{
				SrcMAC:       sA.srcHw,
				DstMAC:       sA.dstHw,
				EthernetType: layers.EthernetTypeARP,
			}
			arp := layers.ARP{
				AddrType:          layers.LinkTypeEthernet,
				Protocol:          layers.EthernetTypeIPv4,
				HwAddressSize:     6,
				ProtAddressSize:   4,
				Operation:         uint16(sA.operation),
				SourceHwAddress:   sA.srcHw,
				SourceProtAddress: sA.srcIp.To4(),
				DstHwAddress:      sA.dstHw,
				DstProtAddress:    sA.dstIp.To4(),
			}
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}

			buff := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(buff, opts, &eth, &arp)
			if err != nil {
				eWriters.Writef("failed to build arp packet: %v", err.Error())
				continue
			}

			// Write the ARP request to the wire
			if err = sA.handle.WritePacketData(buff.Bytes()); err != nil {
				eWriters.Writef("failed to send arp request: %v", err.Error())
				continue
			}
		}
	}
}

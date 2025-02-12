package eavesarp_ng

import (
	"context"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
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

	// arpStringAddrs consists of network addresses in string format that
	// were extracted from an ARP packet.
	arpStringAddrs struct {
		SenIp, SenHw, TarIp, TarHw string
	}

	// ArpSenderArgs represent values needed to send an ARP request.
	ArpSenderArgs struct {
		handle    *pcap.Handle
		operation uint64
		senHw     net.HardwareAddr
		senIp     net.IP
		tarHw     net.HardwareAddr
		tarIp     net.IP
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

			if sA.tarHw == nil {
				if sA.operation == layers.ARPReply {
					eWriters.Write("arp replies require a tarHw value")
					continue
				}
				sA.tarHw = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
			}

			eth := layers.Ethernet{
				SrcMAC:       sA.senHw,
				DstMAC:       sA.tarHw,
				EthernetType: layers.EthernetTypeARP,
			}
			arp := layers.ARP{
				AddrType:          layers.LinkTypeEthernet,
				Protocol:          layers.EthernetTypeIPv4,
				HwAddressSize:     6,
				ProtAddressSize:   4,
				Operation:         uint16(sA.operation),
				SourceHwAddress:   sA.senHw,
				SourceProtAddress: sA.senIp.To4(),
				DstHwAddress:      sA.tarHw,
				DstProtAddress:    sA.tarIp.To4(),
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

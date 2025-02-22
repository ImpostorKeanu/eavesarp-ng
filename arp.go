package eavesarp_ng

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
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
		tarIpRecord *Ip             // current ip db record being resolved for
		senIp       []byte          // sender ip address
		senHw       []byte          // sender hw address
		tarIp       []byte          // target ip address
		tarHw       []byte          // target hardware address
		senderC     chan SendArpCfg // channel used to initiate the arp request
		activeArps  *LockMap[AT]    // track active arp requests
		handle      *pcap.Handle    // handle used to write the arp packet to the wire
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
func SendArp(sA SendArpCfg) error {
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
	if err != nil {
		return fmt.Errorf("failed to build arp packet: %w", err)
	} else if err = sA.Handle.WritePacketData(buff.Bytes()); err != nil {
		return fmt.Errorf("failed to send arp packet: %w", err)
	}

	return nil
}

// doArpRequest configures and sends an ARP request.
func doArpRequest(db *sql.DB, args doArpRequestArgs[ActiveArp], eWriters *EventWriters) {

	eWriters.Writef("initiating active arp request for %v", args.tarIpRecord.Value)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	context.AfterFunc(ctx, func() {
		cancel()
		if err := SetArpResolved(db, args.tarIpRecord.Id); err != nil {
			eWriters.Writef("failed to set arp as resolved: %v", err.Error())
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			eWriters.Writef("never received active arp response for %v", args.tarIpRecord.Value)
		}
		args.activeArps.Delete(args.tarIpRecord.Value)
	})

	args.activeArps.Set(args.tarIpRecord.Value, &ActiveArp{TarIp: args.tarIpRecord, ctx: ctx, cancel: cancel})

	args.senderC <- SendArpCfg{
		Operation: layers.ARPRequest,
		Handle:    args.handle,
		SenderHw:  args.senHw,
		SenderIp:  args.senIp,
		TargetIp:  args.tarIp,
		TargetHw:  args.tarHw,
	}
}

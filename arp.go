package eavesarp_ng

import (
	"context"
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
	// activeArps tracks active ARP requests initiated by the application
	// when an ARP target is passively detected, allowing us to monitor for
	// desired responses.
	activeArps = ActiveArps{sync.RWMutex{}, make(map[string]*ActiveArp)}
	// arpSenderC is used to initiate ARP requests when an ARP target is
	// passively detected.
	arpSenderC = make(chan ArpSenderArgs)
	// stopArpSenderC is used to stop ArpReqSender process.
	stopArpSenderC      = make(chan bool)
	activeArpAlreadySet = errors.New("already set")
	arpSleeper          = NewSleeper(1, 5, 30)
)

const (
	ReqArpOperation ArpOperation = layers.ARPRequest
	RepArpOperation ArpOperation = layers.ARPReply
)

type (
	ArpOperation uint16
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
		handle    *pcap.Handle
		operation ArpOperation
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
		// We do this to avoid database queries in ArpReqSender.
		addActiveArp func() error
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
//
// activeArpAlreadySet is returned when an outstanding request
// is already in activeArps.
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

// ArpReqSender runs as a background process and receives ARP request
// tasks via arpSenderC.
func ArpReqSender() {
	// TODO
	println("starting arp sender process")
	for {
		// SOURCE: https://github.com/google/gopacket/blob/master/examples/arpscan/arpscan.go
		arpSleeper.Sleep()
		select {
		case <-stopArpSenderC:
			break
		case sA := <-arpSenderC:

			if sA.dstHw == nil {
				if sA.operation == RepArpOperation {
					// TODO
					println("arp replies require a dstHw value")
					os.Exit(1)
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
				SourceProtAddress: sA.srcIp,
				DstHwAddress:      sA.dstHw,
				DstProtAddress:    sA.dstIp,
			}
			opts := gopacket.SerializeOptions{
				FixLengths:       true,
				ComputeChecksums: true,
			}

			buff := gopacket.NewSerializeBuffer()
			err := gopacket.SerializeLayers(buff, opts, &eth, &arp)
			if err != nil {
				// TODO logging
				println("build arp request packet", err.Error())
				os.Exit(1)
			}

			//=====================
			// SEND THE ARP REQUEST
			//=====================

			// Add an active ARP record _before_ sending the request to
			// avoid a race condition
			if sA.addActiveArp != nil {
				if err = sA.addActiveArp(); err != nil {
					// TODO logging
					println("failed to add active arp", err.Error())
					os.Exit(1)
				}
			}

			// Write the ARP request to the wire
			if err = sA.handle.WritePacketData(buff.Bytes()); err != nil {
				// TODO
				println("failed to send arp request", err.Error())
				os.Exit(1)
			}
		}
	}
}

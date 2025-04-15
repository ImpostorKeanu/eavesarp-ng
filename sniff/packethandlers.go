package sniff

import (
	"context"
	"database/sql"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	db2 "github.com/impostorkeanu/eavesarp-ng/db"
	"os"
	"sync/atomic"
)

// PacketCounterHandler runs a background routine that sends the count
// of packets captured during an ARP spoofing attack to a channel.
//
// limit indicates that the packet count channel should receive
// a value only after buffSize number of packets have been captured. A
// zero buffSize results in the current count being sent to the channel
// after each packet is received.
func PacketCounterHandler(ctx context.Context, limit int) (chan int, ArpSpoofHandler) {
	var dead atomic.Bool
	cntCh := make(chan int, 100)             // sends the current count to the caller
	pktCh := make(chan gopacket.Packet, 100) // sends packets to the background routine
	kill := reapHandler(&dead, nil, pktCh, cntCh)
	// background routine to watch for packets
	go func() {
		var cnt int
		for {
			select {
			case <-ctx.Done():
				kill(nil)
				return
			case <-pktCh:
				cnt++
				if limit == 0 || cnt%limit == 0 {
					cntCh <- cnt
				}
			}
		}
	}()
	return cntCh, func(pkt gopacket.Packet) {
		if dead.Load() {
			return
		}
		select {
		case <-ctx.Done():
			// NOP
		case pktCh <- pkt:
			// NOP
		}
	}
}

// OutputFileHandler returns a handler function that will write captured
// packets to an output file.
//
// WARNING: the handler closes the file upon return!
func OutputFileHandler(ctx context.Context, f *os.File, errF func(error)) (ArpSpoofHandler, error) {
	writer := pcapgo.NewWriter(f)
	if err := writer.WriteFileHeader(1600, layers.LinkTypeEthernet); err != nil {
		return nil, err
	}
	pktCh := make(chan gopacket.Packet, 100)
	var dead atomic.Bool
	kill := reapHandler(&dead, errF, pktCh)
	go func() {
		defer f.Close()
		for {
			select {
			case <-ctx.Done():
				kill(nil)
				return
			case pkt := <-pktCh:
				err := writer.WritePacket(pkt.Metadata().CaptureInfo, pkt.Data())
				if err != nil {
					kill(err)
					return
				}
			}
		}
	}()
	return func(pkt gopacket.Packet) {
		if dead.Load() {
			return
		}
		select {
		case <-ctx.Done():
			// NOP
		case pktCh <- pkt:
			// NOP
		}
	}, nil
}

// AttackPortHandler ensures that observed ports for the current poisoning attack
// are recorded in the database.
func AttackPortHandler(ctx context.Context, db *sql.DB, attackId int, errF func(error)) ArpSpoofHandler {
	pktCh := make(chan gopacket.Packet, 100)
	var dead atomic.Bool
	kill := reapHandler(&dead, errF, pktCh)
	go func() {
	loop:
		for {
			select {
			case <-ctx.Done():
				kill(nil)
				return
			case pkt := <-pktCh:
				if proto, dstPort, err := GetPacketTransportLayerInfo(pkt); errors.Is(err, NoTransportLayerErr) {
					// NOP
					continue loop
				} else if err != nil {
					kill(err)
					return
				} else {
					// create and associate the observed port
					if port, err := db2.GetOrCreatePort(db, nil, dstPort, proto); err != nil {
						kill(err)
						return
					} else if _, err := db2.GetOrCreateAttackPort(db, attackId, port.Id); err != nil {
						kill(err)
						return
					}
				}
			}
		}
	}()
	return func(pkt gopacket.Packet) {
		if dead.Load() {
			return
		}
		select {
		case <-ctx.Done():
			// NOP
		case pktCh <- pkt:
			// NOP
		}
	}
}

// PacketLimitHandler will run a function once limit packets have been
// captured.
func PacketLimitHandler(ctx context.Context, limit int, onLimitF func()) ArpSpoofHandler {
	pktCh := make(chan gopacket.Packet, 100)
	var dead atomic.Bool
	kill := reapHandler(&dead, nil, pktCh)
	go func() {
		var count int
		for {
			select {
			case <-ctx.Done():
				kill(nil)
				return
			case <-pktCh:
				count++
				if count >= limit {
					onLimitF()
				}
			}
		}
	}()
	return func(pkt gopacket.Packet) {
		if dead.Load() {
			return
		}
		select {
		case <-ctx.Done():
			// NOP
		case pktCh <- pkt:
			// NOP
		}
	}
}

func reapHandler(dead *atomic.Bool, errF func(error), channels ...any) func(error) {
	return func(err error) {
		if !dead.Load() {
			dead.Store(true)
			if err != nil {
				errF(err)
			}
			for _, ch := range channels {
				switch ch := ch.(type) {
				case chan gopacket.Packet:
					close(ch)
				case chan int:
					close(ch)
				default:
					panic("unsupported channel type")
				}
			}
		}
	}
}

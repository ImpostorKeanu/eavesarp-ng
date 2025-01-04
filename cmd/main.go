package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	_ "modernc.org/sqlite"
	"net"
	"os"
	"sync"
	"time"
)

var (
	activeArps          = ActiveArps{sync.RWMutex{}, make(map[string]*ActiveArp)}
	activeArpAlreadySet = errors.New("already set")
	senderChan          = make(chan SenderArgs)
	senderKill          = make(chan bool)
)

type (
	ActiveArp struct {
		DstIp  *eavesarp_ng.Ip
		ctx    context.Context
		cancel context.CancelFunc
	}

	ActiveArps struct {
		mu sync.RWMutex
		v  map[string]*ActiveArp
	}

	UnpackedArp struct {
		SrcIp, SrcHw, DstIp, DstHw string
	}

	SenderArgs struct {
		handle   *pcap.Handle
		srcIface *net.Interface
		addr     *net.IPNet
		dstIp    []byte
	}
)

func ArpSender() {
	// TODO
	println("starting arp sender process")
	for {
		// TODO implement jitter logic here
		select {
		case <-senderKill:
			break
		case sA := <-senderChan:
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
			gopacket.SerializeLayers(buf, opts, &eth, &arp)
			if err := sA.handle.WritePacketData(buf.Bytes()); err != nil {
				// TODO
				println("failed to send arp request", err.Error())
				os.Exit(1)
			}
		}
	}
}

// Get the IP for an active arp.
//
// Note: This method has side effects! It removes the requested
//       ip cancels the job and removes it from the container.
func (a *ActiveArps) Get(ip string) *eavesarp_ng.Ip {
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
func (a *ActiveArps) Add(i *eavesarp_ng.Ip) (err error) {
	if !a.Has(i.Value) {
		a.mu.Lock()
		defer a.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		context.AfterFunc(ctx, func() {
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				// TODO
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
func (a *ActiveArps) Del(ip string) (v *eavesarp_ng.Ip) {
	a.mu.Lock()
	defer a.mu.Unlock()
	v = a.v[ip].DstIp
	delete(a.v, ip)
	return
}

func unpackArp(arp *layers.ARP) UnpackedArp {
	return UnpackedArp{
		SrcIp: net.IP(arp.SourceProtAddress).String(),
		SrcHw: net.HardwareAddr(arp.SourceHwAddress).String(),
		DstIp: net.IP(arp.DstProtAddress).String(),
		DstHw: net.HardwareAddr(arp.DstHwAddress).String(),
	}
}

func main() {
	Sniff(dbTest())
}

func Sniff(db *sql.DB) {

	defer db.Close()
	go ArpSender()
	defer func() {
		// TODO
		println("killing arp sender process")
		senderKill <- true
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
	stop := make(chan any)
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
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

			u := unpackArp(arp)

			switch arp.Operation {
			case layers.ARPRequest:

				//======================================
				// HANDLE PASSIVELY CAPTURED ARP REQUEST
				//======================================

				fmt.Printf("ARP Request: %s (%s) -> %s\n", u.SrcIp, u.SrcHw, u.DstIp)

				_, srcIp, dstIp, err := u.CreateDbValues(db, eavesarp_ng.PassiveArpMeth)

				if dstIp.MacId == nil && !activeArps.Has(dstIp.Value) && !dstIp.ArpResolved {

					//===============================================
					// ACTIVELY SEND AN ARP REQUEST FOR THE SOURCE IP
					//===============================================

					if err := activeArps.Add(dstIp); err != nil && !errors.Is(err, activeArpAlreadySet) {
						// TODO
						println("failed to watch for active arp response", err.Error())
						os.Exit(1)
					}

					senderChan <- SenderArgs{
						handle:   handle,
						srcIface: iface,
						addr:     addr,
						dstIp:    arp.DstProtAddress,
					}

					fmt.Printf("initiated active arp request for %v\n", dstIp.Value)

					_, err = db.Exec(`UPDATE ip SET arp_resolved=1 WHERE id=?`, dstIp.Id)
					//var id int
					//err = eavesarp_ng.GetRow(db, `UPDATE ip SET arp_resolved=1 WHERE id=? RETURNING id`, []any{dstIp.Id}, &id)
					if err != nil {
						// TODO
						println("failed to update arp_resolved attribute", err.Error())
						os.Exit(1)
					}
				}

				//====================
				// INCREMENT ARP COUNT
				//====================

				count, err := eavesarp_ng.IncArpCount(db, srcIp.Id, dstIp.Id)
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
					srcMac, srcIp, _, err := u.CreateDbValues(db, eavesarp_ng.ActiveArpMeth)
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

func (u UnpackedArp) CreateDbValues(db *sql.DB, arpMethod eavesarp_ng.DiscMethod) (srcMac *eavesarp_ng.Mac, srcIp *eavesarp_ng.Ip,
  dstIp *eavesarp_ng.Ip, err error) {

	var created bool

	// goc src mac
	srcMacBuff, created, err := eavesarp_ng.GetOrCreateMac(db, u.SrcHw, arpMethod)
	if err != nil {
		// TODO
		println("failed to create mac: ", err.Error())
		os.Exit(1)
	}
	srcMacBuff.IsNew = created
	srcMac = &srcMacBuff

	// goc src ip
	srcIpBuff, created, err := eavesarp_ng.GetOrCreateIp(db, u.SrcIp, &srcMacBuff.Id, arpMethod, true, false)
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
	srcIpBuff.IsNew = created
	srcIp = &srcIpBuff

	if arpMethod == eavesarp_ng.PassiveArpMeth {
		// goc dst ip
		dstIpBuff, created, err := eavesarp_ng.GetOrCreateIp(db, u.DstIp, nil, arpMethod, false, false)
		if err != nil {
			// TODO
			println("failed to create mac: ", err.Error())
			os.Exit(1)
		}
		dstIpBuff.IsNew = created
		dstIp = &dstIpBuff
	}

	return
}

func dbTest() (db *sql.DB) {
	// Configure connection db
	db, err := sql.Open("sqlite", "/home/archangel/git/eavesarp-ng/junk.sqlite")
	if err != nil {
		println("error", err.Error())
		os.Exit(1)
	}
	//db.SetMaxOpenConns(3)
	//db.SetConnMaxLifetime(0)

	// Get a connection from the db
	//ctx, cancel := context.WithCancel(context.Background())
	//defer cancel()
	//conn, err = db.Conn(ctx)
	//if err != nil {
	//	println("error", err.Error())
	//	os.Exit(1)
	//}

	// Apply schema and configurations
	if _, err = db.ExecContext(context.Background(), eavesarp_ng.SchemaSql); err != nil {
		// TODO
		println("error", err.Error())
		os.Exit(1)
	}

	//mac, err := eavesarp_ng.GetOrCreateMac(conn, "00:00:00:00:00:86", eavesarp_ng.ActiveArpMeth)
	//if err != nil {
	//	println("error", err.Error())
	//	os.Exit(1)
	//} else {
	//	fmt.Printf("Got mac id: %v (%v)\n", mac.Id, mac.DiscMethod)
	//}
	//
	//ip, err := eavesarp_ng.GetOrCreateIp(conn, "192.168.0.86", &mac.Id, eavesarp_ng.PassiveArpMeth, false, false)
	//if err != nil {
	//	println("error", err.Error())
	//	os.Exit(1)
	//} else {
	//	fmt.Printf("Got ip id: %v (%v)\n", ip.Id, ip.DiscMethod)
	//}

	//===============
	// START SNIFFING
	//===============

	//if err = conn.Close(); err != nil {
	//	// TODO
	//}

	return
}

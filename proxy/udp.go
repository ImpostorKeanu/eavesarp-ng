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

type (
	UDPCfg struct {
		connAddrs sync.Map
		log       *zap.Logger
		dataLog   io.Writer
	}

	UDPServer struct {
		Cfg  UDPCfg
		conn *net.UDPConn
	}
)

func (s *UDPServer) Serve(ctx context.Context) (err error) {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			var e error
			var n int
			var addr *net.UDPAddr

			//=====================
			// WAIT FOR UDP TRAFFIC
			//=====================

			// read value larger than the average mtu
			buf := make([]byte, 2048)
			n, addr, e = s.conn.ReadFromUDP(buf)
			if err != nil && errors.Is(e, net.ErrClosed) {
				// listener should be closed only when the context is done
				continue
			} else if err != nil {
				s.Cfg.log.Error("unhandled error while handling udp packet", zap.Error(e))
				continue
			}

			//====================================
			// GET ADDRESS INFORMATION FOR LOGGING
			//====================================

			// get and proxy address info for the connection
			var vAddrInf, pAddrInf misc.Addr
			if pAddrInf, e = misc.NewAddr(s.conn.LocalAddr(), "udp4"); e != nil {
				// TODO
				s.Cfg.log.Error("unhandled error while getting proxy address", zap.Error(e))
				continue
			}

			// look up downstream address information
			var dsAddrInf *misc.Addr
			if vAddrInf, e = misc.NewAddr(addr, "udp"); err != nil {
				s.Cfg.log.Error("failed to parse udp address", zap.Error(e))
				s.Cfg.log.Debug("unhandled error while preparing conntrack info", zap.Error(e))
				continue
			} else if v, ok := s.Cfg.connAddrs.Load(vAddrInf); ok {
				x := v.(misc.Addr)
				dsAddrInf = &x
			}

			// - dsUDPAddr is the downstream address that packets are being proxied to
			// - vUDPAddr is the victim address that will receive datagrams from the downstream
			//   after proxying
			var dsUDPAddr, vUDPAddr *net.UDPAddr
			if dsUDPAddr, e = net.ResolveUDPAddr("udp4", dsAddrInf.String()); e != nil {
				// TODO
				s.Cfg.log.Error("failed to resolve udp address for downstream", zap.Error(e))
				continue
			} else if vUDPAddr, e = net.ResolveUDPAddr("udp4", s.conn.RemoteAddr().String()); e != nil {
				// TODO
				s.Cfg.log.Error("failed to resolve udp address for victim", zap.Error(e))
				continue
			}

			//===================
			// LOG EXTRACTED DATA
			//===================

			var lData misc.Data
			if s.Cfg.dataLog != nil {
				// log data sent by victim
				lData = misc.Data{
					Sender:         misc.VictimDataSender,
					VictimAddr:     vAddrInf,
					ProxyAddr:      pAddrInf,
					DownstreamAddr: dsAddrInf,
					Transport:      misc.UDPTransport,
					Raw:            buf[:n],
				}
				if e := lData.Log(s.Cfg.dataLog); err != nil {
					// TODO
					s.Cfg.log.Error("failed to log data", zap.Error(e))
				}
			} else {
				s.Cfg.log.Error("missing connection info for udp datagram", zap.Any("source", vAddrInf))
				continue
			}

			if dsAddrInf == nil {
				continue
			}

			//===========================================
			// SEND TO DOWNSTREAM AND WAIT FOR A RESPONSE
			//===========================================

			// downstream connection
			var dsUDPConn *net.UDPConn
			if dsUDPConn, e = net.DialUDP("udp4", nil, dsUDPAddr); e != nil {
				// TODO
				s.Cfg.log.Error("failed to dial udp for downstream", zap.Error(e))
				continue
			}

			// proxy to downstream and receive any response
			go func() {
				defer dsUDPConn.Close()
				if _, err := dsUDPConn.Write(buf[:n]); err != nil {
					// TODO
					s.Cfg.log.Error("failed to send udp packet", zap.Error(err))
				}

				// wait for and receive any downstream response to the datagram
				if err = dsUDPConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					// TODO
					s.Cfg.log.Error("failed to set read deadline", zap.Error(err))
				}
				buf := make([]byte, 2048)
				n, err = dsUDPConn.Read(buf)
				if err != nil {
					return
				}

				// reuse old data structure to log data
				lData.Data = ""
				lData.Raw = buf[:n]
				lData.Sender = misc.DownstreamDataSender
				if e := lData.Log(s.Cfg.dataLog); err != nil {
					s.Cfg.log.Error("failed to log data", zap.Error(e))
				}

				// send the downstream response back to the victim via the
				// servers connection
				_, err = s.conn.WriteToUDP(buf[:n], vUDPAddr)
				if err != nil {
					s.Cfg.log.Error("unhandled error while sending udp packet",
						zap.Error(e),
						zap.Any("source", vAddrInf),
						zap.Any("destination", dsAddrInf))
					return
				}
			}()
		}
	}
}

package proxy

import (
	"context"
	"errors"
	"github.com/impostorkeanu/eavesarp-ng/misc"
	"go.uber.org/zap"
	"net"
	"sync"
	"time"
)

type (
	UDPCfg struct {
		connAddrs sync.Map
		log       *zap.Logger
	}

	UDPServer struct {
		cfg  UDPCfg
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

			// read value larger than the average mtu
			buf := make([]byte, 2048)
			n, addr, e = s.conn.ReadFromUDP(buf)
			if err != nil && errors.Is(e, net.ErrClosed) {
				// listener should be closed only when the context is done
				continue
			} else if err != nil {
				s.cfg.log.Error("unhandled error while handling udp packet", zap.Error(e))
				continue
			}

			// TODO log data

			// look up downstream address information
			var key, ds misc.Addr
			if key, e = misc.NewAddr(addr, "udp"); err != nil {
				s.cfg.log.Error("failed to parse udp address", zap.Error(e))
				s.cfg.log.Debug("unhandled error while preparing conntrack info", zap.Error(e))
			} else if v, ok := s.cfg.connAddrs.Load(key); ok {
				ds = v.(misc.Addr)
			} else {
				s.cfg.log.Error("missing connection info for udp datagram", zap.Any("source", key))
				continue
			}

			// dsAddr is the downstream address that packets are being proxied to
			// vAddr is the victim address that will receive datagrams from the downstream
			//   after proxying
			var dsAddr, vAddr *net.UDPAddr
			if dsAddr, e = net.ResolveUDPAddr("udp4", ds.String()); e != nil {
				// TODO
				s.cfg.log.Error("failed to resolve udp address for downstream", zap.Error(e))
				continue
			}
			if vAddr, e = net.ResolveUDPAddr("udp4", s.conn.RemoteAddr().String()); e != nil {
				// TODO
				s.cfg.log.Error("failed to resolve udp address for victim", zap.Error(e))
				continue
			}

			// downstream connection
			var dsConn *net.UDPConn
			if dsConn, e = net.DialUDP("udp4", nil, dsAddr); e != nil {
				// TODO
				s.cfg.log.Error("failed to dial udp for downstream", zap.Error(e))
				continue
			}

			// proxy to downstream and receive any response
			go func() {
				defer dsConn.Close()
				if _, err := dsConn.Write(buf[:n]); err != nil {
					s.cfg.log.Error("failed to send udp packet", zap.Error(err))
				}

				// wait for and receive any downstream response to the datagram
				if err = dsConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
					s.cfg.log.Error("failed to set read deadline", zap.Error(err))
				}
				buf := make([]byte, 2048)
				n, err = dsConn.Read(buf)
				if err != nil {
					return
				}

				// TODO response log data

				// send the downstream response back to the victim via the
				// servers connection
				_, err = s.conn.WriteToUDP(buf[:n], vAddr)
				if err != nil {
					s.cfg.log.Error("unhandled error while sending udp packet",
						zap.Error(e),
						zap.Any("source", key),
						zap.Any("destination", ds))
					return
				}
			}()
		}
	}
}

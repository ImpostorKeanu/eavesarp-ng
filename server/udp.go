package server

import (
	"context"
	"errors"
	"go.uber.org/zap"
	"net"
)

type (
	UDPOpts struct {
		Addr string
	}
)

func ServeUDP(ctx context.Context, conn *net.UDPConn, log *zap.Logger) (err error) {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			var e error
			buf := make([]byte, 2048)
			n, addr, e := conn.ReadFromUDP(buf)
			if err != nil && errors.Is(e, net.ErrClosed) {
				// listener should be closed only when the context is done
				continue
			} else if err != nil {
				log.Error("unhandled error while handling udp packet", zap.Error(e))
				continue
			}
			// TODO log data
		}
	}
}

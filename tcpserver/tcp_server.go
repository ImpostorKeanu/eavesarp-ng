package tcpserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"go.uber.org/zap"
	"net"
)

type (
	// TCPOpts specifies options to start a TLS-aware TCP
	// server that will receive TCP connections when no downstream is
	// configured for a poisoning attack.
	TCPOpts struct {
		// Addr is the address the TCP server will listen on. Notes:
		//
		// - Expected format: `127.0.0.1:8686`
		// - If the value is empty (""), the server will start on localhost
		//   with a random port
		// - This is likely always going to be a localhost address
		Addr string
		// TLSCfg is the configuration used to initialize TLS connections.
		TLSCfg *tls.Config
		// GetRespBytes is a function that allows for random data to
		// be generated and sent in the TCP response.
		GetRespBytes RespFunc
	}

	// peekConn lets us peek at traffic and fingerprint potential TLS
	// connections.
	peekConn struct {
		net.Conn
		b *bufio.Reader
	}

	// RespFunc defines a function signature that returns
	// bytes for TCP segments.
	RespFunc func() ([]byte, error)
)

// Peek at the connection.
func (c *peekConn) Peek(n int) ([]byte, error) {
	return c.b.Peek(n)
}

// Read from the connection.
func (c *peekConn) Read(b []byte) (n int, err error) {
	return c.b.Read(b)
}

func Serve(ctx context.Context, l net.Listener, opts TCPOpts, log *zap.Logger) (err error) {
	if opts.TLSCfg == nil {
		return errors.New("tls config is required for default tcp server")
	}

	context.AfterFunc(ctx, func() {
		if err := l.Close(); err != nil {
			log.Error("failed to close default tcp listener", zap.Error(err))
		}
	})

ctrl:
	for {
		select {
		case <-ctx.Done():
			break ctrl
		default:

			// block and wait for connection OR cancellation
			var conn net.Conn
			conn, err = l.Accept()

			if errors.Is(err, net.ErrClosed) {
				err = nil
				log.Info("default tcp server closed")
				break ctrl
			} else if err != nil {
				log.Error("default tcp server failed to accept tcp connection", zap.Error(err))
				break ctrl
			}

			// handle the connection in a distinct routine
			go func() {
				if err := handleConn(conn, opts, log); err != nil {
					log.Error("failed to handle default tcp connection", zap.Error(err))
				}
			}()

		}
	}

	return
}

func handleConn(conn net.Conn, opts TCPOpts, log *zap.Logger) (err error) {

	// always call close on the connection
	defer func() {
		if err := conn.Close(); err != nil {
			log.Error("failed to close default tcp connection", zap.Error(err))
		}
	}()

	// wrap the connection so we can determine if it's tls
	conn = &peekConn{
		Conn: conn,
		b:    bufio.NewReader(conn),
	}

	// fingerprint and upgrade tls
	b, err := conn.(*peekConn).Peek(3)
	if isHandshake(b) {
		conn = tls.Server(conn, opts.TLSCfg)
		if err = conn.(*tls.Conn).Handshake(); err != nil {
			log.Error("failed to tls handshake default tcp connection", zap.Error(err))
			return
		}
	}

	// read from the connection
	b = make([]byte, 1)
	_, err = conn.Read(b)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		log.Error("failed to read default tcp connection (connection closed)", zap.Error(err))
		return
	} else if err != nil {
		log.Error("failed to read default tcp connection", zap.Error(err))
		return
	}

	// get response bytes from function and write to connection
	b, err = opts.GetRespBytes()
	if err != nil {
		log.Error("failed to get response for default tcp connection", zap.Error(err))
		return
	}
	if _, err = conn.Write(b); err != nil {
		log.Error("failed to write default tcp connection", zap.Error(err))
	}

	return
}

// isHandshake reads the first two bytes of buff and checks for
// a TLS client hello.
func isHandshake(buf []byte) bool {
	// TODO SSL is no longer supported by the tls package
	//  may need to see about implementing it manually
	// https://tls12.xargs.org/#client-hello/annotated
	if len(buf) >= 2 && buf[0] == 0x16 && buf[1] == 0x03 {
		return true
	}
	return false
}

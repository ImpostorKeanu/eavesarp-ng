package eavesarp_ng

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"io"
	"log"
	"net"
	"sync"
)

var (
	tlsConfig *tls.Config
	tlsCert   tls.Certificate
)

func init() {
	var err error
	if tlsCert, err = tls.LoadX509KeyPair("/tmp/cert.pem", "/tmp/key.pem"); err != nil {
		log.Fatal(err)
	}
	tlsConfig = &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       []tls.Certificate{tlsCert},
	}
}

type (
	// proxyListener provides configuration information to the
	// embedded net.Listener while overriding Accept.
	proxyListener struct {
		net.Listener
		cfg Cfg
	}

	// proxyConn maps the local connection to the downstream connection.
	proxyConn struct {
		net.Conn
		peeker     *peekConn
		downstream *downstreamConn
		tlsConn    *tls.Conn
		mu         sync.RWMutex
		cfg        Cfg
	}

	peekConn struct {
		net.Conn
		buf *bufio.Reader
	}

	downstreamConn struct {
		net.Conn
		proxy *proxyConn
	}

	//peekConn struct {
	//	net.Conn
	//	parent *proxyConn
	//}

	// ProxyServer proxies TCP traffic to downstream servers during AITM
	// attacks.
	ProxyServer struct {
		// cfg is used to obtain the proper listening address the
		// ProxyServer will listen on.
		cfg Cfg
		// refC is the count of proxyConn instances using the
		// server and is used to determine when it's safe to
		// shut down.
		refC refCounter
	}

	// proxyDownstream has details necessary to contact the
	// downstream server during an AITM attack.
	proxyDownstream struct {
		addr net.IP
	}

	// proxyRef tracks the cancel function and count of
	// references for a ProxyServer by local socket, allowing us
	// to determine if any AITM attacks are using the server and
	// if the ProxyServer can be stopped.
	proxyRef struct {
		mu *sync.RWMutex
		// cancel to be called once rC is zero.
		cancel context.CancelFunc
		// rC tracks the number of aitmDownstreams instances
		// using this downstream. Once at zero, the associated
		// proxy listener can be shut down.
		rC *refCounter
	}
)

func (u *downstreamConn) Write(b []byte) (n int, err error) {
	u.proxy.mu.RLock()
	if u.proxy.tlsConn != nil {
		u.Conn = tls.Client(u.Conn, &tls.Config{InsecureSkipVerify: false})
	}
	u.proxy.mu.RUnlock()
	return u.Conn.Write(b)
}

func isHandshake(buf []byte) bool {
	// TODO SSL is no longer supported by the tls package
	//  may need to see about implementing it manually

	// https://tls12.xargs.org/#client-hello/annotated
	if len(buf) >= 2 && buf[0] == 0x16 && buf[1] == 0x03 {
		return true
	}
	return false
}

func newProxyListener(cfg Cfg, port int) (*proxyListener, error) {
	l, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", cfg.ipNet.IP.String(), port))
	return &proxyListener{Listener: l, cfg: cfg}, err
}

func (c *peekConn) Peek(n int) ([]byte, error) {
	return c.buf.Peek(n)
}

func (c *peekConn) Read(b []byte) (n int, err error) {
	return c.buf.Read(b)
}

func (c *peekConn) isHandshake() bool {
	peek, err := c.Peek(5)
	if err != nil {
		// TODO handle error
		return false
	}
	return isHandshake(peek)
}

func (c *proxyConn) Write(b []byte) (n int, err error) {
	if c.tlsConn != nil {
		return c.tlsConn.Write(b)
	}
	return c.Conn.Write(b)
}

func (c *proxyConn) Read(b []byte) (n int, err error) {

	if c.tlsConn == nil && c.peeker.isHandshake() {

		c.cfg.log.Debug("upgrading server connection to tls")
		c.mu.Lock()
		c.tlsConn = tls.Server(c.peeker, tlsConfig)
		c.mu.Unlock()
		if err = c.tlsConn.Handshake(); err != nil {
			// TODO handle handshake error
			c.cfg.log.Error("tls handshake failure", zap.Error(err))
		}
		return c.tlsConn.Read(b)

	} else if c.tlsConn != nil {

		return c.tlsConn.Read(b)

	}

	return c.peeker.Read(b)
}

// Accept calls net.Listener.Accept and establishes a connection with
// the AITM downstream, returning an error when either step fails. Both
// connections are closed if an error occurs.
func (l *proxyListener) Accept() (c *proxyConn, err error) {

	//==========================
	// ACCEPT INBOUND CONNECTION
	//==========================

	c = &proxyConn{cfg: l.cfg}
	c.Conn, err = l.Listener.Accept() // block until connection
	if err != nil {
		if c.Conn != nil {
			c.Conn.Close()
		}
		return
	}
	c.peeker = &peekConn{Conn: c.Conn, buf: bufio.NewReader(c.Conn)}

	//==================================================
	// ESTABLISH CONNECTION WITH DOWNSTREAM FOR PROXYING
	//==================================================

	var (
		cIp  string           // ip of client that initiated connection
		port string           // port the proxy and downstream are listening on
		u    *proxyDownstream // where to connect
	)

	// get ip of the client
	cIp, _, err = net.SplitHostPort(c.RemoteAddr().String())

	// get the downstream address set by the aitm config
	if u = l.cfg.aitmDownstreams.Get(cIp); u == nil {
		return c, errors.New("no aitm downstream for connection")
	}

	// get the port of the local proxy server, which matches the listening
	// port of the downstream server
	if _, port, err = net.SplitHostPort(c.LocalAddr().String()); err != nil {
		return
	}

	// connect to the downstream
	c.downstream = &downstreamConn{
		proxy: c,
	}
	c.downstream.Conn, err =
	  net.Dial("tcp4", fmt.Sprintf("%s:%s", u.addr.To4().String(), port))

	if err != nil {
		if c.Conn != nil {
			c.Conn.Close()
		}
	}

	return c, err
}

// handle proxying a TCP connection.
func (c *proxyConn) handle(ctx context.Context, decCh chan int) {
	context.AfterFunc(ctx, func() {
		// close connections
		if c.Conn != nil {
			c.Conn.Close()
		}
		if c.downstream != nil {
			c.downstream.Close()
		}
		decCh <- 1 // tell ProxyServer that a connection has died
	})

	go io.Copy(c, c.downstream) // put one side of the connection in routine
	// block until one side of the connection dies
	if _, err := io.Copy(c.downstream, c); err != nil {
		// TODO handle the error
	}
}

// handleRefCounter runs in a distinct routine and listens
// on conDeathCh to determine when a connection has died,
// indicating that the reference counter should be decremented.
// Kill the routine by sending to diCh.
func (s *ProxyServer) handleRefCounter(conDeathCh, dieCh chan int) {
	for {
		select {
		case <-dieCh:
			return
		case <-conDeathCh:
			// decrement the reference counter
			s.refC.dec()
		}
	}
}

// Serve TCP connections on port.
func (s *ProxyServer) Serve(ctx context.Context, port int) (err error) {

	var l *proxyListener
	if l, err = newProxyListener(s.cfg, port); err != nil {
		return
	}

	context.AfterFunc(ctx, func() {
		// TODO
		l.Close()
	})

	conDeathCh := make(chan int) // used by connections to indicate death
	killRefCh := make(chan int)  // used to tell the reference counter routine to die

	// routine to watch for connection deaths
	go s.handleRefCounter(conDeathCh, killRefCh)

ctrl:
	for {
		select {
		case <-ctx.Done():
			break ctrl
		default:
			//====================================
			// WAIT FOR AND HANDLE NEXT CONNECTION
			//====================================

			// wait for next connection
			c, e := l.Accept()
			if e != nil {
				if !errors.Is(e, net.ErrClosed) {
					err = e
				}
				break
			}
			// increment the reference counter
			s.refC.inc()
			// handle the connection in a new routine
			//pC := c.(*proxyConn)
			go c.handle(ctx, conDeathCh)
		}
	}

	// stop the routine used to watch for connection deaths
	killRefCh <- 0
	close(killRefCh)

	// wait for all connections to die
	for c := s.refC.count(); c > 0; <-conDeathCh {
		if c, err = s.refC.dec(); err != nil {
			// todo handle and log error from decrementing reference counter
			err = nil
		}
	}
	close(conDeathCh)

	return
}

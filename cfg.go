package eavesarp_ng

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"github.com/florianl/go-nfqueue/v2"
	"github.com/google/nftables"
	"github.com/impostorkeanu/eavesarp-ng/crt"
	"github.com/impostorkeanu/eavesarp-ng/misc"
	"github.com/impostorkeanu/eavesarp-ng/misc/rand"
	"github.com/impostorkeanu/eavesarp-ng/nft"
	"github.com/impostorkeanu/eavesarp-ng/proxy"
	gs "github.com/impostorkeanu/gosplit"
	"go.uber.org/zap"
	"io"
	_ "modernc.org/sqlite"
	"net"
	"slices"
	"sync"
	"sync/atomic"
)

const (
	DefaultDownstreamOptWeight int = iota
	TCPProxyServerOptWeight
	UDPProxyServerOptWeight
)

type (
	Cfg struct {
		id      string
		nftConn *nftables.Conn
		nfqConn *nfqueue.Nfqueue
		db      *sql.DB
		ipNet   *net.IPNet
		iface   *net.Interface
		log     *zap.Logger
		dataLog io.Writer
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
		// connMap maps the sender address to a target address for a connection
		// that has been detected by netfilter.
		//
		// The type for both the key and value is misc.Addr.
		connMap *sync.Map

		// defDownstreamIP describes a TCP listener that will receive connections
		// during an AITM attack _without_ an AITM downstream. This allows us to
		// always complete TCP connections and receive data.
		//
		// Type: *misc.Addr
		//
		// See: getDefDownstream, setDefDownstream
		defDownstreamIP atomic.Value

		// tcpProxyAddr is the address to the default TCP proxy used by
		// all connections.
		//
		// Type: *misc.Addr
		//
		// See: getTCPProxyAddr, setTCPProxyAddr
		tcpProxyAddr atomic.Value

		udpProxyAddr atomic.Value

		// nftTbl is the netfilter table created for the current Cfg.
		nftTbl *nftables.Table
	}

	// LocalTCPProxyServerAddrOpt sets the default TCP proxy for poisoned
	// connections.
	//
	// When supplied to NewCfg and empty, a TCP listener will be started
	// on a randomly available port of cfg.iface.
	LocalTCPProxyServerAddrOpt string

	// LocalUDPProxyServerAddrOpt sets the default UDP proxy for poisoned
	// traffic.
	//
	// When supplied to NewCfg and empty, a UDP listener will be started
	// on a randomly available port of cfg.iface.
	LocalUDPProxyServerAddrOpt string

	// DefaultDownstreamOpt sets the default downstream for AITM attacks.
	//
	// When not supplied or empty, the server specified by TCPOpts
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
// - LocalTCPProxyServerAddrOpt
// - LocalUDPProxyServerAddrOpt
// - DefaultDownstreamOpt
func NewCfg(dsn string, ifaceName, ifaceAddr string, log *zap.Logger, dataLog io.Writer, opts ...any) (cfg Cfg, err error) {

	// configure logging
	if log == nil {
		err = errors.New("nil logger")
		return
	}
	cfg.log = log
	cfg.dataLog = dataLog

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

	cfg.aitm.connMap = new(sync.Map)

	//============================================
	// APPLY OPTIONS AND START SUPPORTING ROUTINES
	//============================================

	var ctx context.Context
	ctx, cfg.cancel = context.WithCancel(context.Background())

	// TLS private key generation and certificate caching
	cfg.tls = tlsCfgFields{
		cache: crt.NewCache(&gs.RSAPrivKeyGenerator{}),
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
		case LocalTCPProxyServerAddrOpt:
			if err = cfg.StartTCPProxy(ctx, string(v)); err != nil {
				return
			}
		case LocalUDPProxyServerAddrOpt:
			if err = cfg.StartUDPProxy(ctx, string(v)); err != nil {
				return
			}
		case DefaultDownstreamOpt:
			if err = cfg.SetDefaultDS(string(v)); err != nil {
				return
			}
		}
	}

	// initialize the netfilter table and dnat rules
	if err = cfg.InitNetfilter(ctx, cfg.aitm.getTCPProxyAddr(), cfg.aitm.getUDPProxyAddr()); err != nil {
		cfg.log.Error("failed to init netfilter table", zap.Error(err))
	}

	return
}

func (cfg *Cfg) SetDefaultDS(addr string) (err error) {
	var x net.IP
	if x = net.ParseIP(addr); x == nil {
		err = errors.New("failed to parse ip for default downstream")
	}
	if err != nil {
		err = fmt.Errorf("failed to parse default downstream value: %w", err)
	} else {
		cfg.aitm.setDefDownstream(x)
	}
	return
}

func (cfg *Cfg) emptyAddr(addr string) (string, error) {
	if cfg.ipNet == nil {
		return "", errors.New("nil ipNet")
	}
	if addr == "" {
		addr = net.JoinHostPort(cfg.ipNet.IP.String(), "0")
	}
	return addr, nil
}

func (cfg *Cfg) StartUDPProxy(ctx context.Context, addr string) error {

	var err error
	if addr, err = cfg.emptyAddr(addr); err != nil {
		return fmt.Errorf("invalid address value: %w", err)
	}

	var x *net.UDPAddr
	x, err = net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve address for udp: %w", err)
	}

	var conn *net.UDPConn
	if conn, err = net.ListenUDP("udp4", x); err != nil {
		return fmt.Errorf("failed to listen udp: %w", err)
	}

	var a misc.Addr
	if a.IP, a.Port, err = net.SplitHostPort(conn.LocalAddr().String()); err != nil {
		return fmt.Errorf("failed to get udp listener address: %w", err)
	}

	a.Transport = misc.UDPTransport
	cfg.aitm.setUDPProxyAddr(a)
	cfg.log.Info("local udp proxy server listener started", zap.String("address", conn.LocalAddr().String()))
	go func() {
		pCfg := proxy.NewUDPCfg(cfg.aitm.connMap, cfg.log, cfg.dataLog)
		if e := proxy.NewUDPServer(pCfg, conn).Serve(ctx); e != nil {
			cfg.log.Error("udp proxy server failed", zap.Error(e))
			cfg.errC <- err
		}
	}()

	return nil

}

// StartTCPProxy runs a proxy server in a distinct routine that will receive
// all proxied connections via DNAT.
func (cfg *Cfg) StartTCPProxy(ctx context.Context, addr string) error {
	var err error
	if addr, err = cfg.emptyAddr(addr); err != nil {
		return fmt.Errorf("invalid address value: %w", err)
	}

	var l net.Listener
	if l, err = net.Listen("tcp4", addr); err != nil {
		return fmt.Errorf("failed to listen on tcp tcp: %w", err)
	}

	var a misc.Addr
	if a.IP, a.Port, err = net.SplitHostPort(l.Addr().String()); err != nil {
		return fmt.Errorf("failed to get tcp listener address: %w", err)
	}

	a.Transport = misc.TCPTransport
	cfg.aitm.setTCPProxyAddr(a)
	cfg.log.Info("local tcp proxy server listener started", zap.String("address", l.Addr().String()))
	go func() {
		pCfg := proxy.NewTCPCfg(cfg.aitm.connMap, cfg.GetProxyCertificateFunc, cfg.log, cfg.dataLog)
		if e := gs.NewProxyServer(pCfg, l).Serve(ctx); e != nil {
			cfg.log.Error("default tcp proxy server failed", zap.Error(e))
			cfg.errC <- err
		}
	}()

	return nil
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
	if cfg.nfqConn != nil {
		if err := cfg.nfqConn.Close(); err != nil {
			cfg.log.Error("failed to close nfqueue connection", zap.Error(err))
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

// GetProxyCertificateFunc returns a function that generates and/or serves
// an X509 certificate for a downstream.
//
// If the handshake includes a server name value, the CN is that value. It's
// otherwise the IP addressof the downstream.
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
		k, err := crt.NewCacheKey(cn, ips, dnsNames)
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

func (f *aitmCfgFields) setUDPProxyAddr(a misc.Addr) {
	f.udpProxyAddr.Store(&a)
}

func (f *aitmCfgFields) getUDPProxyAddr() (a *misc.Addr) {
	a, _ = f.udpProxyAddr.Load().(*misc.Addr)
	return
}

// getTCPProxyAddr gets the address of the default TCP proxy.
func (f *aitmCfgFields) getTCPProxyAddr() (a *misc.Addr) {
	a, _ = f.tcpProxyAddr.Load().(*misc.Addr)
	return
}

// setTCPProxyAddr sets the address of the default TCP proxy.
func (f *aitmCfgFields) setTCPProxyAddr(a misc.Addr) {
	f.tcpProxyAddr.Store(&a)
}

// getDefDownstream gets the default downstream.
func (f *aitmCfgFields) getDefDownstream() (a net.IP) {
	a, _ = f.defDownstreamIP.Load().(net.IP)
	return
}

// setDefDownstream sets the default downstream.
func (f *aitmCfgFields) setDefDownstream(a net.IP) {
	f.defDownstreamIP.Store(a)
}

// InitNetfilter initializes the Netfilter table used to DNAT traffic
// to the routines that proxy traffic to downstreams.
func (cfg *Cfg) InitNetfilter(ctx context.Context, tcpProxyAddr, udpProxyAddr *misc.Addr) error {

	if tcpProxyAddr == nil && udpProxyAddr == nil {
		return errors.New("no tcp proxy or udp proxy configured; skipping nft table initialization")
	}

	// initialize netfilter connection
	var err error
	if cfg.nftConn, err = nftables.New(nftables.AsLasting()); err != nil { // init netfilter conn
		return fmt.Errorf("failed to establish nft connection: %w", err)
	} else if err = cfg.newRandID(5); err != nil { // generate random id for the table
		return fmt.Errorf("failed to generate cfg id: %w", err)
	} else if err = nft.StaleTables(cfg.nftConn, cfg.log); err != nil { // warn about stale tables
		return fmt.Errorf("failed to list stale nft tables: %w", err)
	} else if cfg.aitm.nftTbl, err = nft.CreateTable(cfg.nftConn, nft.TableName(cfg.id), cfg.log); err != nil { // create a table for the config
		return fmt.Errorf("failed to init nft table: %w", err)
	}

	// create a dnat rule for tcp
	if tcpProxyAddr != nil {
		if _, err = nft.CreateDNATRule(cfg.nftConn, cfg.aitm.nftTbl, tcpProxyAddr); err != nil {
			return fmt.Errorf("failed to create tcp nft dnat rule: %w", err)
		}
	}

	// create a dnat rule for udp
	if udpProxyAddr != nil {
		if _, err = nft.CreateDNATRule(cfg.nftConn, cfg.aitm.nftTbl, udpProxyAddr); err != nil {
			return fmt.Errorf("failed to create udp nft dnat rule: %w", err)
		}
	}

	cfg.log.Info("successfully initialized nft table", zap.String("nft_table_name", cfg.aitm.nftTbl.Name))

	// delete the nft table upon ctx cancel
	context.AfterFunc(ctx, func() {
		tName := nft.TableName(cfg.id)
		cfg.log.Debug("deleting current nft table", zap.String("nft_table_name", tName))
		if err := nft.DelTable(cfg.nftConn, cfg.aitm.nftTbl); err != nil {
			cfg.log.Error("failed to delete nft table during shutdown",
				zap.Error(err),
				zap.String("table_name", tName))
		} else {
			cfg.log.Debug("deleted nft table", zap.String("nft_table_name", tName))
		}
	})

	return nil
}

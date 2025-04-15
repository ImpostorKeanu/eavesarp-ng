package sniff

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"github.com/florianl/go-conntrack"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/nftables"
	"github.com/impostorkeanu/eavesarp-ng/crt"
	"github.com/impostorkeanu/eavesarp-ng/db"
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

// Option weights are used to sort options passed to NewCfg,
// allowing us to manage dependencies as various routines
// are started.
const (
	DefaultDownstreamOptWeight int = iota
	TCPProxyServerOptWeight
	UDPProxyServerOptWeight
)

type (
	// Cfg is the primary eavesarp configuration type that binds
	// all connections and data sources together.
	//
	// NewCfg initializes this type while starting all supporting
	// routines.
	Cfg struct {
		// id is a randomly generated value for the cfg.
		//
		// It's used to ensure uniqueness of NFT tables.
		id     string
		db     *sql.DB            // db connection to the SQLite database.
		ipNet  *net.IPNet         // ipNet the config is managing.
		iface  *net.Interface     // iface the config is managing.
		log    *zap.Logger        // log to receive log records.
		dataW  io.Writer          // dataW sends JSON data to the writer.
		errC   chan error         // errC communicates errors to other applications.
		arp    arpCfgFields       // arp resolution and configuration.
		dns    dnsCfgFields       // dns resolution and configuration.
		tls    tlsCfgFields       // tls cert generation and caching.
		aitm   aitmCfgFields      // aitm tracks data and configurations associated with AITM attacks.
		cancel context.CancelFunc // cancel function called upon exit.
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
		// downstreams maps sender addresses to downstream addresses.
		//
		//
		// This allows for traffic to be relayed by associating the pre-DNAT
		// port with a downstream (destination) IP address.
		//
		// The type for both the key and value is misc.Addr.
		downstreams *sync.Map

		// spoofed maps source addresses to ARP addresses that have been spoofed.
		//
		// This reveals the pre-DNAT destination address that
		// spoofed via sniff.AttackSnac.
		//
		// The key type is a string formatted as SRC_IP:SRC_PORT
		//
		// map["SRC_IP:SRC_PORT"]=ORIG_DST_IP
		spoofed *sync.Map

		// defDownstreamIP describes a TCP listener that will receive connections
		// during an AITM attack _without_ an AITM downstream. This allows us to
		// always complete TCP connections and receive data.
		//
		// Type: *misc.Addr
		//
		// See: GetDefDownstreamIP, SetDefDownstreamIP
		defDownstreamIP atomic.Value

		// tcpProxyAddr is the address to the TCP proxy used by
		// all connections.
		//
		// Type: *misc.Addr
		//
		// See: GetTCPProxyAddr, SetTCPProxyAddr
		tcpProxyAddr atomic.Value

		// udpProxyAddr is the address to the UDP proxy used for
		// all data.
		//
		// Type: *misc.Addr
		//
		// See: GetUDPProxyAddr, SetUDPProxyAddr
		udpProxyAddr atomic.Value

		// nftConn is used to manage the nft table that DNATs traffic to
		// the TCP and UDP intercepting proxy.
		nftConn *nftables.Conn

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

	if cfg.aitm.nftConn == nil {
		return errors.New("nftable connection is nil")
	}
	for {
		cfg.id, err = rand.String(int64(l))
		if err != nil {
			return fmt.Errorf("failed to generate cfg id: %w", err)
		}
		if t, _ := cfg.aitm.nftConn.ListTable(nft.TableName(cfg.id)); t == nil {
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
	cfg.dataW = dataLog

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

	cfg.aitm.downstreams = new(sync.Map)
	cfg.aitm.spoofed = new(sync.Map)

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
			var addr net.Addr
			if addr, err = cfg.StartTCPProxy(ctx, string(v)); err != nil {
				return
			} else {
				cfg.log.Info("tcp proxy server listener started", zap.String("address", addr.String()))
			}
		case LocalUDPProxyServerAddrOpt:
			var addr net.Addr
			if addr, err = cfg.StartUDPProxy(ctx, string(v)); err != nil {
				return
			} else {
				cfg.log.Info("udp proxy server listener started", zap.String("address", addr.String()))
			}
		case DefaultDownstreamOpt:
			var ip net.IP
			if ip = net.ParseIP(string(v)); ip == nil {
				err = errors.New("failed to parse ip for default downstream")
				return
			}
			if err != nil {
				err = fmt.Errorf("failed to parse default downstream value: %w", err)
				return
			} else {
				cfg.aitm.SetDefDownstreamIP(ip)
			}
		}
	}

	if cfg.aitm.GetTCPProxyAddr() != nil || cfg.aitm.GetUDPProxyAddr() != nil {
		// initialize the netfilter table and dnat rules
		if err = cfg.InitNetfilter(ctx, cfg.aitm.GetTCPProxyAddr(), cfg.aitm.GetUDPProxyAddr()); err != nil {
			cfg.log.Error("failed to init netfilter table", zap.Error(err))
		}
	} else {
		cfg.log.Warn("no tcp or udp proxies configured; skipping nft table creation")
	}

	return
}

// StartUDPProxy starts a UDP proxy on addr.
func (cfg *Cfg) StartUDPProxy(ctx context.Context, addr string) (net.Addr, error) {

	var err error
	if addr, err = cfg.emptyAddr(addr); err != nil {
		return nil, fmt.Errorf("invalid address value: %w", err)
	}

	var x *net.UDPAddr
	x, err = net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address for udp: %w", err)
	}

	var conn *net.UDPConn
	if conn, err = net.ListenUDP("udp4", x); err != nil {
		return nil, fmt.Errorf("failed to listen udp: %w", err)
	}

	var a misc.Addr
	if a.IP, a.Port, err = net.SplitHostPort(conn.LocalAddr().String()); err != nil {
		return nil, fmt.Errorf("failed to get udp listener address: %w", err)
	}

	a.Transport = misc.UDPTransport
	cfg.aitm.SetUDPProxyAddr(a)
	go func() {
		pCfg := proxy.NewUDPCfg(cfg.aitm.downstreams, cfg.log, cfg.dataW)
		if e := proxy.NewUDPServer(pCfg, conn).Serve(ctx); e != nil {
			cfg.log.Error("udp proxy server failed", zap.Error(e))
			cfg.errC <- err
		}
	}()

	return conn.LocalAddr(), nil
}

// StartTCPProxy runs a proxy server in a distinct routine that will receive
// all proxied connections via DNAT.
func (cfg *Cfg) StartTCPProxy(ctx context.Context, addr string) (net.Addr, error) {
	var err error
	if addr, err = cfg.emptyAddr(addr); err != nil {
		return nil, fmt.Errorf("invalid address value: %w", err)
	}

	var l net.Listener
	if l, err = net.Listen("tcp4", addr); err != nil {
		return nil, fmt.Errorf("failed to listen on tcp tcp: %w", err)
	}

	var a misc.Addr
	if a.IP, a.Port, err = net.SplitHostPort(l.Addr().String()); err != nil {
		return nil, fmt.Errorf("failed to get tcp listener address: %w", err)
	}

	a.Transport = misc.TCPTransport
	cfg.aitm.SetTCPProxyAddr(a)
	go func() {
		pCfg := proxy.NewTCPCfg(cfg.aitm.downstreams, cfg.aitm.spoofed, cfg.GetProxyCertificateFunc, cfg.log, cfg.dataW)
		if e := gs.NewProxyServer(pCfg, l).Serve(ctx); e != nil {
			cfg.log.Error("default tcp proxy server failed", zap.Error(e))
			cfg.errC <- err
		}
	}()

	return l.Addr(), nil
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
	if cfg.aitm.nftConn != nil {
		if err := cfg.aitm.nftConn.CloseLasting(); err != nil {
			cfg.log.Error("failed to close nftable connection", zap.Error(err))
		}
	}
	close(cfg.arp.ch)
	close(cfg.dns.ch)
	close(cfg.errC)
}

// initDb initializes a SQLite database for eavesarp-ng.
func (cfg *Cfg) initDb(dsn string) (conn *sql.DB, err error) {
	conn, err = sql.Open("sqlite", dsn)
	if err != nil {
		cfg.log.Error("error opening db", zap.Error(err))
		return
	}
	conn.SetMaxOpenConns(1)
	// TODO test the connection by pinging the database
	_, err = conn.ExecContext(context.Background(), db.SchemaSql)
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
// otherwise the IP address of the downstream.
func (cfg *Cfg) GetProxyCertificateFunc(victimIP, downstreamIP string) func(h *tls.ClientHelloInfo) (cert *tls.Certificate, error error) {

	return func(h *tls.ClientHelloInfo) (cert *tls.Certificate, err error) {

		// TODO h.ServerName could reveal an unknown hostname

		var dnsNames []string
		ips := []string{victimIP}
		cn := victimIP
		if h.ServerName != "" {
			// common name is server name when set
			cn = h.ServerName
			ips = append(ips)
		}

		//========================================
		// QUERY DATABASE FOR DOWNSTREAM DNS NAMES
		//========================================

		var rows *sql.Rows
		rows, err = cfg.db.Query(`
SELECT dns_name.value FROM ip
INNER JOIN dns_record ON dns_record.ip_id=ip.id
INNER JOIN dns_name ON dns_name.id=dns_record.dns_name_id
WHERE ip.value=? AND dns_record.kind="a"`, downstreamIP)

		if err != nil {
			cfg.log.Error("error querying dns names from database", zap.Error(err))
			return
		}
		defer rows.Close()

		// read rows
		for rows.Next() {
			var dn string
			if err = rows.Scan(&dn); err != nil {
				cfg.log.Error("error scanning dns names from database", zap.Error(err))
				return
			} else {
				dnsNames = append(dnsNames, dn)
			}
		}

		//===============================
		// GET AND/OR CACHE A CERTIFICATE
		//===============================

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

// SetUDPProxyAddr sets the address of the UDP proxy.
func (f *aitmCfgFields) SetUDPProxyAddr(a misc.Addr) {
	f.udpProxyAddr.Store(&a)
}

// GetUDPProxyAddr gets the address for the UDP proxy.
func (f *aitmCfgFields) GetUDPProxyAddr() (a *misc.Addr) {
	a, _ = f.udpProxyAddr.Load().(*misc.Addr)
	return
}

// GetTCPProxyAddr gets the address of the default TCP proxy.
func (f *aitmCfgFields) GetTCPProxyAddr() (a *misc.Addr) {
	a, _ = f.tcpProxyAddr.Load().(*misc.Addr)
	return
}

// SetTCPProxyAddr sets the address of the default TCP proxy.
func (f *aitmCfgFields) SetTCPProxyAddr(a misc.Addr) {
	f.tcpProxyAddr.Store(&a)
}

// GetDefDownstreamIP gets the default downstream.
func (f *aitmCfgFields) GetDefDownstreamIP() (a net.IP) {
	a, _ = f.defDownstreamIP.Load().(net.IP)
	return
}

// SetDefDownstreamIP sets the default downstream.
func (f *aitmCfgFields) SetDefDownstreamIP(a net.IP) {
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
	if cfg.aitm.nftConn, err = nftables.New(nftables.AsLasting()); err != nil { // init netfilter conn
		return fmt.Errorf("failed to establish nft connection: %w", err)
	} else if err = cfg.newRandID(5); err != nil { // generate random id for the table
		return fmt.Errorf("failed to generate cfg id: %w", err)
	} else if err = nft.StaleTables(cfg.aitm.nftConn, cfg.log); err != nil { // warn about stale tables
		return fmt.Errorf("failed to list stale nft tables: %w", err)
	} else if cfg.aitm.nftTbl, err = nft.CreateTable(cfg.aitm.nftConn, nft.TableName(cfg.id), cfg.log); err != nil { // create a table for the config
		return fmt.Errorf("failed to init nft table: %w", err)
	}

	// create a dnat rule for tcp
	if tcpProxyAddr != nil {
		if _, err = nft.CreateDNATRule(cfg.aitm.nftConn, cfg.aitm.nftTbl, tcpProxyAddr); err != nil {
			return fmt.Errorf("failed to create tcp nft dnat rule: %w", err)
		}
	}

	// create a dnat rule for udp
	if udpProxyAddr != nil {
		if _, err = nft.CreateDNATRule(cfg.aitm.nftConn, cfg.aitm.nftTbl, udpProxyAddr); err != nil {
			return fmt.Errorf("failed to create udp nft dnat rule: %w", err)
		}
	}

	cfg.log.Info("successfully initialized nft table", zap.String("nft_table_name", cfg.aitm.nftTbl.Name))

	// delete the nft table upon ctx cancel
	context.AfterFunc(ctx, func() {
		tName := nft.TableName(cfg.id)
		cfg.log.Debug("deleting current nft table", zap.String("nft_table_name", tName))
		if err := nft.DelTable(cfg.aitm.nftConn, cfg.aitm.nftTbl); err != nil {
			cfg.log.Error("failed to delete nft table during shutdown",
				zap.Error(err),
				zap.String("table_name", tName))
		} else {
			cfg.log.Debug("deleted nft table", zap.String("nft_table_name", tName))
		}
	})

	return nil
}

// emptyAddr returns the default IP of the config's network interface
// configuration with a zero port should addr be empty.
//
// Passing a zero port value results in selection of a random port
// when passed to StartTCPProxy and StartUDPProxy.
func (cfg *Cfg) emptyAddr(addr string) (string, error) {
	if cfg.ipNet == nil {
		return "", errors.New("nil ipNet")
	}
	if addr == "" {
		addr = net.JoinHostPort(cfg.ipNet.IP.String(), "0")
	}
	return addr, nil
}

// mapConn updates the connection and spoofed IP maps with information
// to enable post-DNAT connectivity and TLS certificate generation.
//
// No update is made if:
//
// - downstream is nil
// - the packet doesn't have an IPv4, TCP, or UDP layer.
//
// Spoofed IPs are stored only for TCP connections.
func (cfg *Cfg) mapConn(packet gopacket.Packet, downstream net.IP) {

	if ipL, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {

		//==============================================
		// HANDLE INCOMING TCP CONNECTIONS & UDP PACKETS
		//==============================================

		k := misc.Addr{IP: ipL.SrcIP.To4().String()}
		v := misc.Addr{IP: downstream.To4().String()}

		if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok && tcp.SYN {
			k.Port = fmt.Sprintf("%d", tcp.SrcPort)
			k.Transport = misc.TCPTransport
			v.Port = fmt.Sprintf("%d", tcp.DstPort)
			v.Transport = misc.TCPTransport
			cfg.aitm.spoofed.Store(k.String(), ipL.DstIP.To4().String())
		} else if udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
			// TODO should probably look into refining this
			//  one of the benefits of conntrack is that it could infer the state
			//  of a UDP "connection"....
			k.Port = fmt.Sprintf("%d", udp.SrcPort)
			k.Transport = misc.UDPTransport
			v.Port = fmt.Sprintf("%d", udp.DstPort)
			v.Transport = misc.UDPTransport
		}

		if k.Port == "" {
			return
		}
		cfg.aitm.downstreams.Store(k, v)
	}

	return
}

// destroyConnFilterFunc returns a hook for cleaning up destroyed
// UDP and TCP connections.
func (cfg *Cfg) destroyConnFilterFunc() conntrack.HookFunc {
	return func(con conntrack.Con) int {
		// dereferencing this pointer may seem reckless, but it's fine
		// because the filter only accepts tcp/udp traffic
		t := misc.ConntrackTransportFromProtoNum(*con.Origin.Proto.Number)
		if t == "" {
			return 0
		}
		k := misc.Addr{
			IP:        con.Origin.Src.To4().String(),
			Port:      fmt.Sprintf("%d", *con.Origin.Proto.SrcPort),
			Transport: t}
		cfg.aitm.downstreams.Delete(k)
		if k.Transport == misc.TCPTransport {
			cfg.aitm.spoofed.Delete(k.String())
		}
		cfg.log.Debug("cleaning destroyed connection",
			zap.Any("source", k),
			zap.String("transport", string(t)))
		return 0
	}
}

// optInt returns an integer weight assigned to known NewCfg options.
func optInt(v any) (i int, err error) {
	switch v.(type) {
	case DefaultDownstreamOpt:
		i = DefaultDownstreamOptWeight
	case LocalTCPProxyServerAddrOpt:
		i = TCPProxyServerOptWeight
	case LocalUDPProxyServerAddrOpt:
		i = UDPProxyServerOptWeight
	default:
		err = errors.New("unknown opt type")
	}
	return
}

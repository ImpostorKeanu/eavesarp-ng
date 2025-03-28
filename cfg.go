package eavesarp_ng

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	gs "github.com/impostorkeanu/gosplit"
	"go.uber.org/zap"
	"net"
)

type (
	Cfg struct {
		db             *sql.DB
		ipNet          *net.IPNet
		iface          *net.Interface
		log            *zap.Logger
		errC           chan error          // Channel to communicate errors to other applications
		arpSenderC     chan SendArpCfg     // Sends ARP requests and responses to the ARP SenderServer routine.
		activeArps     *LockMap[ActiveArp] // Track ARP ongoing requests.
		dnsSenderC     chan DoDnsCfg       // Sends DNS requests to the DNS SenderServer routine.
		activeDns      *LockMap[DoDnsCfg]  // Track ongoing DNS transactions.
		dnsFailCounter *FailCounter        // Track DNS failures
		tls            tlsCfgFields
		aitm           aitmCfgFields
	}

	tlsCfgFields struct {
		keygen *gs.RSAPrivKeyGenerator
	}

	aitmCfgFields struct {
		// downstreams maps the sender IP of an AITM attack to a downstream
		// that will receive proxied connections, allowing us to use a single
		// ProxyServer listening on a local port for multiple downstreams.
		downstreams *LockMap[proxyDownstream]
		// defDownstream describes a TCP listener that will receive connections
		// during an AITM attack that _without_ an AITM target. This allows us to complete
		// the TCP connection and receive TCP segments even when an attack is not
		// configured with a downstream.
		defDownstream *proxyDownstream
		// proxies tracks proxies by local socket.
		//
		// Used to send traffic to downstream servers during an AITM attack.
		proxies *LockMap[proxyRef]

		defTCPServerCancel context.CancelFunc
	}

	// proxyDownstream has details necessary to contact the
	// downstream server during an AITM attack.
	proxyDownstream struct {
		ip, port string
	}
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
func NewCfg(dsn string, ifaceName, ifaceAddr string, log *zap.Logger, opts ...any) (cfg Cfg, err error) {

	// require a logger
	if log == nil {
		err = errors.New("nil logger")
		return
	}
	cfg.log = log

	cfg.errC = make(chan error, 1) // channel to communicate errors
	if err = cfg.getInterface(ifaceName, ifaceAddr); err != nil {
		return
	}

	cfg.dnsSenderC = make(chan DoDnsCfg, 50)
	cfg.activeDns = NewLockMap(make(map[string]*DoDnsCfg))

	cfg.arpSenderC = make(chan SendArpCfg, 50)
	cfg.activeArps = NewLockMap(make(map[string]*ActiveArp))

	cfg.db, err = cfg.initDb(dsn)
	cfg.dnsFailCounter = NewFailCounter(DnsMaxFailures)

	cfg.aitm.downstreams = NewLockMap(make(map[string]*proxyDownstream))
	cfg.aitm.proxies = NewLockMap(make(map[string]*proxyRef))

	cfg.tls.keygen = &gs.RSAPrivKeyGenerator{}
	if err = cfg.tls.keygen.Start(2048); err != nil {
		return
	}

	for _, opt := range opts {
		switch v := opt.(type) {
		case DefaultTCPServerOpts:
			err = cfg.StartDefaultTCPServer(&v)
		}
	}

	return
}

// StartDefaultTCPServer starts a TLS aware TCP server that will act as a downstream
// for incoming connections for spoofing attacks that do not have a downstream
// configured. This ensures that all TCP connections can complete and send packets.
func (cfg *Cfg) StartDefaultTCPServer(opts *DefaultTCPServerOpts) (err error) {

	//=========================
	// START DEFAULT TCP SERVER
	//=========================
	// - catches all TCP connections when a poisoning attack doesn't
	//   have a downstream configured

	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:0"
	}

	// start a listener on a random port for the default tcp server
	var defTCPL net.Listener
	defTCPL, err = net.Listen("tcp4", opts.Addr)
	if err != nil {
		cfg.log.Error("failed to start default tcp server", zap.Error(err))
		return
	}
	opts.Addr = defTCPL.Addr().String()
	cfg.log.Info("default tcp server listener started", zap.String("address", opts.Addr))

	// capture listener the address
	cfg.aitm.defDownstream = &proxyDownstream{}
	cfg.aitm.defDownstream.ip, cfg.aitm.defDownstream.ip, _ = net.SplitHostPort(defTCPL.Addr().String())

	// start the tcp server in a distinct routine
	defCtx, cancel := context.WithCancel(context.Background())
	go func() {
		cfg.log.Debug("default tcp server accepting connections", zap.String("address", opts.Addr))
		e := ServeDefaultTCP(defCtx, defTCPL, cfg, *opts)
		if e != nil {
			cfg.log.Error("default tcp server error", zap.Error(e))
			cancel()
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
	if cfg.db != nil {
		cfg.db.Close()
	}
	if cfg.aitm.defTCPServerCancel != nil {
		cfg.aitm.defTCPServerCancel()
	}
	if cfg.tls.keygen != nil {
		cfg.tls.keygen.Stop()
	}
	close(cfg.arpSenderC)
	close(cfg.dnsSenderC)
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

//==========================
// GoSplit INTERFACE METHODS
//==========================

func (cfg *Cfg) RecvListenerAddr(addr gs.ProxyListenerAddr) {
	if cfg.aitm.defDownstream != nil {
		return
	}
	cfg.aitm.defDownstream = &proxyDownstream{ip: addr.IP, port: addr.Port}
	cfg.aitm.downstreams.Set("default", cfg.aitm.defDownstream)
}

func (cfg *Cfg) RecvConnStart(i gs.ConnInfo) {
	//TODO implement me
	panic("implement me")
}

func (cfg *Cfg) RecvConnEnd(i gs.ConnInfo) {
	//TODO implement me
	panic("implement me")
}

func (cfg *Cfg) RecvVictimData(i gs.ConnInfo, b []byte) {
	//TODO implement me
	panic("implement me")
}

func (cfg *Cfg) RecvDownstreamData(i gs.ConnInfo, b []byte) {
	//TODO implement me
	panic("implement me")
}

func (cfg *Cfg) RecvLog(r gs.LogRecord) {
	//TODO implement me
	panic("implement me")
}

func (cfg *Cfg) GetProxyTLSConfig(proxyA gs.ProxyAddr, vicA gs.VictimAddr) (*tls.Config, error) {
	//TODO implement me
	panic("implement me")
}

func (cfg *Cfg) GetDownstreamAddr(proxyA gs.ProxyAddr, vicA gs.VictimAddr) (ip string, port string, err error) {
	//TODO implement me
	panic("implement me")
}

func (cfg *Cfg) GetDownstreamTLSConfig(proxyA gs.ProxyAddr, vicA gs.VictimAddr) (*tls.Config, error) {
	//TODO implement me
	panic("implement me")
}

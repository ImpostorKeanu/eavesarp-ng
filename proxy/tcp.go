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
	TCPCfg struct {
		log                  *zap.Logger
		dLog                 io.Writer
		connAddrs            *sync.Map
		downstreamCertGetter DsCertGetter
	}
	DsCertGetter func(downstreamIP string) func(*tls.ClientHelloInfo) (*tls.Certificate, error)
)

var (
	dsTLSCfg = &tls.Config{
		InsecureSkipVerify: true,
	}
)

func NewTCPCfg(connAddrs *sync.Map, downstreamCertGetter DsCertGetter, log *zap.Logger, dataLog io.Writer) *TCPCfg {
	return &TCPCfg{
		log:                  log,
		connAddrs:            connAddrs,
		downstreamCertGetter: downstreamCertGetter,
		dLog:                 dataLog,
	}
}

//==========================
// GoSplit INTERFACE METHODS
//==========================

func (cfg *TCPCfg) RecvVictimData(cI gs.ConnInfo, b []byte) {
	if cfg.dLog == nil {
		return
	}
	data := connInfoToData(cI, b, misc.VictimDataSender)
	if err := data.Log(cfg.dLog); err != nil {
		cfg.log.Error("failed to write victim data to log", zap.Error(err))
	}
}

func (cfg *TCPCfg) RecvDownstreamData(cI gs.ConnInfo, b []byte) {
	if cfg.dLog == nil {
		return
	}
	data := connInfoToData(cI, b, misc.DownstreamDataSender)
	if err := data.Log(cfg.dLog); err != nil {
		cfg.log.Error("failed to write downstream data to log", zap.Error(err))
	}
}

// RecvConnStart to implement gosplit.ConnInfoReceiver.
func (cfg *TCPCfg) RecvConnStart(i gs.ConnInfo) {
	cfg.log.Debug("new connection started", zap.Any("conn", i))
}

// RecvConnEnd to implement gosplit.ConnInfoReceiver
//
// This removes the cfg.connAddrs entry for the current connection.
func (cfg *TCPCfg) RecvConnEnd(i gs.ConnInfo) {
	cfg.log.Debug("connection ended", zap.Any("conn", i))
	cfg.connAddrs.Delete(misc.Addr{
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
		if d, ok := cfg.connAddrs.Load(misc.Addr{IP: vicA.IP, Port: vicA.Port, Transport: misc.TCPTransport}); ok {
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

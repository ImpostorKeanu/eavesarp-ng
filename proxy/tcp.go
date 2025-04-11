package proxy

import (
	"crypto/tls"
	"fmt"
	"github.com/impostorkeanu/eavesarp-ng/misc"
	gs "github.com/impostorkeanu/gosplit"
	"go.uber.org/zap"
	"sync"
	"time"
)

type (
	TCPCfg struct {
		log                  *zap.Logger
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

func NewTCPCfg(connAddrs *sync.Map, downstreamCertGetter DsCertGetter, log *zap.Logger) *TCPCfg {
	return &TCPCfg{
		log:                  log,
		connAddrs:            connAddrs,
		downstreamCertGetter: downstreamCertGetter,
	}
}

//==========================
// GoSplit INTERFACE METHODS
//==========================

//func (cfg *TCPCfg) RecvVictimData(i gs.ConnInfo, b []byte) {
//	//TODO implement me
//	panic("implement me")
//}
//
//func (cfg *TCPCfg) RecvDownstreamData(i gs.ConnInfo, b []byte) {
//	//TODO implement me
//	panic("implement me")
//}

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
		IP: i.VictimAddr.IP, Port: i.VictimAddr.Port,
		Transport: misc.TCPAddrTransport})
}

func (cfg *TCPCfg) RecvLog(r gs.LogRecord) {
	cfg.log.Info("received log event from tcp proxy", zap.Any("record", r))
}

func (cfg *TCPCfg) GetProxyTLSConfig(_ gs.ProxyAddr, _ gs.VictimAddr, dsA gs.DownstreamAddr) (*tls.Config, error) {
	return &tls.Config{
		InsecureSkipVerify: true,
		GetCertificate:     cfg.downstreamCertGetter(dsA.IP),
	}, nil
}

func (cfg *TCPCfg) GetDownstreamAddr(_ gs.ProxyAddr, vicA gs.VictimAddr) (ip string, port string, err error) {
	// try to retrieve downstream connection a few times
	for i := 0; i < 10; i++ {
		if ds, ok := cfg.connAddrs.Load(misc.Addr{IP: vicA.IP, Port: vicA.Port, Transport: misc.TCPAddrTransport}); ok {
			ip, port = ds.(misc.Addr).IP, ds.(misc.Addr).Port
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	err = fmt.Errorf("victim ip (%s) has no downstream set", vicA.IP)
	return
}

func (cfg *TCPCfg) GetDownstreamTLSConfig(_ gs.ProxyAddr, _ gs.VictimAddr, _ gs.DownstreamAddr) (*tls.Config, error) {
	return dsTLSCfg, nil
}

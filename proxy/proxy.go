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
	Cfg struct {
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

func NewCfg(connAddrs *sync.Map, downstreamCertGetter DsCertGetter, log *zap.Logger) *Cfg {
	return &Cfg{
		log:                  log,
		connAddrs:            connAddrs,
		downstreamCertGetter: downstreamCertGetter,
	}
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
	cfg.connAddrs.Delete(gs.Addr{
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
		GetCertificate:     cfg.downstreamCertGetter(dsA.IP),
	}, nil
}

func (cfg *Cfg) GetDownstreamAddr(_ gs.ProxyAddr, vicA gs.VictimAddr) (ip string, port string, err error) {
	// try to retrieve downstream connection a few times
	for i := 0; i < 10; i++ {
		if ds, ok := cfg.connAddrs.Load(misc.ConntrackInfo{Addr: misc.Addr{IP: vicA.IP, Port: vicA.Port}, Transport: misc.TCPConntrackTransport}); ok {
			ip, port = ds.(misc.ConntrackInfo).IP, ds.(misc.ConntrackInfo).Port
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

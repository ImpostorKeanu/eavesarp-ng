package eavesarp_ng

import (
	"context"
	"github.com/impostorkeanu/eavesarp-ng/misc"
	"github.com/impostorkeanu/eavesarp-ng/nft"
	"github.com/impostorkeanu/eavesarp-ng/server"
	"github.com/impostorkeanu/eavesarp-ng/tcpserver"
	"go.uber.org/zap"
	"net"
	"testing"
)

func newCfg() (cfg Cfg, err error) {
	logger := zap.NewExample()
	return NewCfg("/tmp/eatest.db", "enp13s0", "", logger,
		DefaultProxyServerAddrOpt(""), server.TCPOpts{
			GetRespBytes: func() ([]byte, error) {
				return []byte("stuff"), nil
			},
		})
}

func TestAttackSnac(t *testing.T) {

	cfg, err := newCfg()
	if err != nil {
		t.Fatal(err)
	}

	sIP := net.ParseIP("192.168.86.3")
	tIP := net.ParseIP("192.168.86.99")
	if err = nft.AddSpoofedIP(cfg.nftConn, cfg.aitm.nftTbl, tIP); err != nil {
		t.Fatal(err)
	}

	type args struct {
		ctx        context.Context
		cfg        Cfg
		senIp      net.IP
		tarIp      net.IP
		downstream *misc.Addr
		handlers   []ArpSpoofHandler
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "testo", args: args{context.TODO(), cfg, sIP, tIP, nil, nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := make(chan AttackSnacCfg)
			go func() {
				if err := MainSniff(context.Background(), cfg, ch); err != nil {
					t.Fatal(err)
				}
			}()

			if err := AttackSnac(tt.args.ctx, &tt.args.cfg, tt.args.senIp, tt.args.tarIp, tt.args.downstream, tt.args.handlers...); (err != nil) != tt.wantErr {
				t.Errorf("AttackSnac() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

package sniff

import (
	"context"
	"github.com/impostorkeanu/eavesarp-ng/nft"
	"go.uber.org/zap"
	"net"
	"os"
	"testing"
)

func newCfg() (cfg Cfg, err error) {
	logger := zap.NewExample()
	return NewCfg("/tmp/eatest.db", "enp13s0", "", logger,
		os.Stdout,
		LocalTCPProxyServerAddrOpt(""),
		LocalUDPProxyServerAddrOpt(""),
		//DefaultDownstreamOpt(""),
	)
}

func TestAttackSnac(t *testing.T) {

	cfg, err := newCfg()
	if err != nil {
		t.Fatal(err)
	}

	sIP := net.ParseIP("192.168.86.3")
	tIP := net.ParseIP("192.168.86.99")
	if err = nft.AddSpoofedIP(cfg.aitm.nftConn, cfg.aitm.nftTbl, tIP); err != nil {
		t.Fatal(err)
	}

	type args struct {
		ctx           context.Context
		cfg           Cfg
		senIp         net.IP
		tarIp         net.IP
		tcpDownstream net.IP
		handlers      []ArpSpoofHandler
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "testo", args: args{context.TODO(), cfg, sIP, tIP, net.ParseIP("192.168.86.174"), nil}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ch := make(chan AttackSnacCfg)
			go func() {
				if err := Main(context.Background(), cfg, ch); err != nil {
					t.Fatal(err)
				}
			}()

			if err := AttackSnac(tt.args.ctx, &tt.args.cfg, tt.args.senIp, tt.args.tarIp, tt.args.tcpDownstream, tt.args.handlers...); (err != nil) != tt.wantErr {
				t.Errorf("AttackSnac() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

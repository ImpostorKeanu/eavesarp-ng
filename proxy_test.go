package eavesarp_ng

import (
	"context"
	"go.uber.org/zap"
	"net"
	"testing"
)

func TestProxyServer_Serve(t *testing.T) {
	type fields struct {
		cfg Cfg
	}
	type args struct {
		ctx  context.Context
		port int
	}

	logger := zap.NewExample()
	cfg, _ := NewCfg("/tmp/junk", "enp13s0", "192.168.86.174", logger)

	cfg.aitmDownstreams.Set("192.168.86.174", &proxyDownstream{addr: net.ParseIP("192.168.86.3").To4()})

	//ctx, cancel := context.WithTimeout(context.TODO(), 5*time.Second)
	ctx := context.TODO()

	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{"initial", fields{cfg: cfg}, args{ctx: ctx, port: 8080}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &ProxyServer{
				cfg: tt.fields.cfg,
			}
			if err := s.Serve(tt.args.ctx, tt.args.port); (err != nil) != tt.wantErr {
				t.Errorf("Serve() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	//cancel()
}

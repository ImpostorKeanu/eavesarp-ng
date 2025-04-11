package eavesarp_ng

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"github.com/impostorkeanu/eavesarp-ng/tcpserver"
	gs "github.com/impostorkeanu/gosplit"
	"go.uber.org/zap"
	"testing"
)

func TestCfg_StartDefaultTCPServer(t *testing.T) {

	var err error
	keygen := &gs.RSAPrivKeyGenerator{}
	if err = keygen.Start(2048); err != nil {
		return
	}
	var crt *tls.Certificate
	crt, err = gs.GenSelfSignedCert(pkix.Name{}, nil, nil, keygen.Generate())
	if err != nil {
		t.Error("error generating self signed certificate for default tcp server", zap.Error(err))
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	logger, _ := zap.NewDevelopment()
	errChan := make(chan error)

	type fields struct {
		log      *zap.Logger
		errC     chan error
		aitmVals aitmCfgFields
	}

	type args struct {
		opts *tcpserver.TCPOpts
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{name: "default", fields: fields{log: logger, errC: errChan}, args: args{opts: &tcpserver.TCPOpts{
			Addr: "",
			TLSCfg: &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{*crt},
			},
			GetRespBytes: func() ([]byte, error) {
				return []byte("stuff"), nil
			},
		}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Cfg{
				log:  tt.fields.log,
				errC: tt.fields.errC,
				//aitmCfgFields: tt.fields.aitmVals,
			}
			if err := cfg.StartDefaultTCPServer(ctx, tt.args.opts); (err != nil) != tt.wantErr {
				t.Errorf("StartDefaultTCPServer() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err := <-cfg.Err(); (err != nil) != tt.wantErr {
				t.Errorf("StartDefaultTCPServer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	cancel()
}

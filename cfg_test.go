package eavesarp_ng

import (
	"go.uber.org/zap"
	"testing"
)

func TestCfg_StartDefaultTCPServer(t *testing.T) {

	logger, _ := zap.NewDevelopment()
	errChan := make(chan error)

	type fields struct {
		log      *zap.Logger
		errC     chan error
		aitmVals aitmCfgFields
	}

	type args struct {
		opts *DefaultTCPServerOpts
	}

	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{name: "default", fields: fields{log: logger, errC: errChan}, args: args{opts: &DefaultTCPServerOpts{
			Addr:   "",
			TlsCFG: nil,
			GetRespBytes: func() ([]byte, error) {
				return []byte("stuff"), nil
			},
		}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Cfg{
				log:           tt.fields.log,
				errC:          tt.fields.errC,
				aitmCfgFields: tt.fields.aitmVals,
			}
			if err := cfg.StartDefaultTCPServer(tt.args.opts); (err != nil) != tt.wantErr {
				t.Errorf("StartDefaultTCPServer() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err := <-cfg.Err(); (err != nil) != tt.wantErr {
				t.Errorf("StartDefaultTCPServer() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

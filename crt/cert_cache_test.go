package crt

import (
	"github.com/impostorkeanu/eavesarp-ng/misc/rand"
	"testing"
)

func TestNewCertCacheKey(t *testing.T) {
	type args struct {
		commonName string
		ips        []string
		dnsNames   []string
	}

	baseArgs := args{commonName: "test.com", ips: []string{"192.168.1.1"}, dnsNames: []string{"test1.com,", "test2.com"}}

	ips := []string{"192.168.1.1"}

	tests := []struct {
		name    string
		args    args
		want    *CacheKey
		wantErr bool
	}{
		{name: "valid", args: baseArgs, want: &CacheKey{commonName: baseArgs.commonName, dnsNames: baseArgs.dnsNames, ips: ips}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewCacheKey(tt.args.commonName, tt.args.ips, tt.args.dnsNames)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewCacheKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func Test_randString(t *testing.T) {
	type args struct {
		maxLen int64
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "1", args: args{maxLen: 2}, wantErr: false},
		{name: "2", args: args{maxLen: 5}, wantErr: false},
		{name: "3", args: args{maxLen: 20}, wantErr: false},
		{name: "4", args: args{maxLen: 30}, wantErr: false},
		{name: "5", args: args{maxLen: 7}, wantErr: false},
		{name: "6", args: args{maxLen: 100}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotS, err := rand.String(tt.args.maxLen)
			if (err != nil) != tt.wantErr {
				t.Errorf("String() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			t.Logf("String(%v) = %v", tt.args.maxLen, gotS)
			if int64(len(gotS)) != tt.args.maxLen {
				t.Errorf("String() len(gotS) = %v, want %v", len(gotS), tt.args.maxLen)
			}
		})
	}
}

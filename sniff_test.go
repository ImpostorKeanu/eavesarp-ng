package eavesarp_ng

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/google/gopacket"
	_ "modernc.org/sqlite"
	"net"
	"os"
	"testing"
	"time"
)

func readyDb() (db *sql.DB) {
	db, err := sql.Open("sqlite", "/home/archangel/git/eavesarp-ng/junk.sqlite")
	if err != nil {
		println("error", err.Error())
		os.Exit(1)
	}
	if _, err = db.ExecContext(context.Background(), SchemaSql); err != nil {
		// TODO
		println("error", err.Error())
		os.Exit(1)
	}
	return
}

func TestSniff(t *testing.T) {
	db := readyDb()
	t.Run("sniff", func(t *testing.T) {
		Sniff(db, "enp13s0")
	})
}

func TestSnacSniff(t *testing.T) {

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	counterC := make(chan bool)
	counter := func() {
		for c := 0; c < 10; c++ {
			select {
			case <-counterC:
			}
		}
		cancel()
	}

	t.Run("snac", func(t *testing.T) {
		go counter()
		SnacSniff(ctx, "enp13s0", net.ParseIP("192.168.2.6"), func(p gopacket.Packet) {
			counterC <- true
			proto, port, _ := GetPacketTransportLayerInfo(p)
			fmt.Printf("Got packet: %s/%d\n", proto, port)
		})
	})
}

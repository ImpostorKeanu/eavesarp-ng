package main

import (
	"context"
	"database/sql"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	_ "modernc.org/sqlite"
	"os"
)

func main() {
	// Configure connection pool
	pool, err := sql.Open("sqlite", "/home/archangel/git/eavesarp-ng/junk.sqlite")
	if err != nil {
		println("error", err.Error())
		os.Exit(1)
	}
	pool.SetMaxOpenConns(3)
	pool.SetConnMaxLifetime(0)

	// Get a connection from the pool
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	uiConn, err := pool.Conn(ctx)
	if err != nil {
		println("error", err.Error())
		os.Exit(1)
	}

	// Apply schema and configurations
	if _, err = uiConn.ExecContext(context.Background(), eavesarp_ng.SchemaSql); err != nil {
		// TODO
		println("error", err.Error())
		os.Exit(1)
	}

	//mac, err := eavesarp_ng.GetOrCreateMac(uiConn, "00:00:00:00:00:86", eavesarp_ng.ArpDiscMethodPassive)
	//if err != nil {
	//	println("error", err.Error())
	//	os.Exit(1)
	//} else {
	//	fmt.Printf("Got mac id: %v (%v)\n", mac.Id, mac.ArpDiscMethod)
	//}
	//
	//ip, err := eavesarp_ng.GetOrCreateIp(uiConn, "192.168.0.86", &mac.Id, eavesarp_ng.IpDiscMethodPassiveArp, false, false)
	//if err != nil {
	//	println("error", err.Error())
	//	os.Exit(1)
	//} else {
	//	fmt.Printf("Got ip id: %v (%v)\n", ip.Id, ip.DiscMethod)
	//}

	//===============
	// START SNIFFING
	//===============

	if err = uiConn.Close(); err != nil {
		// TODO
	}
}

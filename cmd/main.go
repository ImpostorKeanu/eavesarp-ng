package main

import (
	"context"
	"database/sql"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	_ "modernc.org/sqlite"
	"os"
)

func main() {
	eavesarp_ng.Sniff(dbTest())
}

func dbTest() (db *sql.DB) {
	// Configure connection db
	db, err := sql.Open("sqlite", "/home/archangel/git/eavesarp-ng/junk.sqlite")
	if err != nil {
		println("error", err.Error())
		os.Exit(1)
	}
	db.SetMaxOpenConns(3)
	db.SetConnMaxLifetime(0)

	// Get a connection from the db
	//ctx, cancel := context.WithCancel(context.Background())
	//defer cancel()
	//conn, err = db.Conn(ctx)
	//if err != nil {
	//	println("error", err.Error())
	//	os.Exit(1)
	//}

	// Apply schema and configurations
	if _, err = db.ExecContext(context.Background(), eavesarp_ng.SchemaSql); err != nil {
		// TODO
		println("error", err.Error())
		os.Exit(1)
	}

	//mac, err := eavesarp_ng.GetOrCreateMac(conn, "00:00:00:00:00:86", eavesarp_ng.ActiveArpMeth)
	//if err != nil {
	//	println("error", err.Error())
	//	os.Exit(1)
	//} else {
	//	fmt.Printf("Got mac id: %v (%v)\n", mac.Id, mac.DiscMethod)
	//}
	//
	//ip, err := eavesarp_ng.GetOrCreateIp(conn, "192.168.0.86", &mac.Id, eavesarp_ng.PassiveArpMeth, false, false)
	//if err != nil {
	//	println("error", err.Error())
	//	os.Exit(1)
	//} else {
	//	fmt.Printf("Got ip id: %v (%v)\n", ip.Id, ip.DiscMethod)
	//}

	//===============
	// START SNIFFING
	//===============

	//if err = conn.Close(); err != nil {
	//	// TODO
	//}

	return
}

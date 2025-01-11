package main

import (
	"context"
	"database/sql"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	_ "modernc.org/sqlite"
	"os"
)

func main() {
	// Configure connection db
	db, err := sql.Open("sqlite", "/home/archangel/git/eavesarp-ng/junk.sqlite")
	if err != nil {
		println("error", err.Error())
		os.Exit(1)
	}

	// TODO test the connection by pinging the database
	db.SetMaxOpenConns(3)
	db.SetConnMaxLifetime(0)

	// Apply schema and configurations
	if _, err = db.ExecContext(context.Background(), eavesarp_ng.SchemaSql); err != nil {
		// TODO
		println("error", err.Error())
		os.Exit(1)
	}

	//===============
	// START SNIFFING
	//===============

	//if err = conn.Close(); err != nil {
	//	// TODO
	//}

	eavesarp_ng.MainSniff(db, "enp13s0")

	return
}

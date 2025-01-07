package eavesarp_ng

import (
	"context"
	"database/sql"
	_ "modernc.org/sqlite"
	"os"
	"testing"
)

func TestSniff(t *testing.T) {
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
	t.Run("sniff", func(t *testing.T) {
		Sniff(db)
	})
}

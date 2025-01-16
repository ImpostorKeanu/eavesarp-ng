package main

import (
	"fmt"
	"testing"
)

func TestRun(t *testing.T) {

	dbFile = "/home/archangel/git/eavesarp-ng/junk.sql"

	db, err := initDb(dbFile)
	if err != nil {
		fmt.Printf("error initializing database: %s\n", err.Error())
		panic(err)
	}

	defer func() {
		if err := db.Close(); err != nil {
			fmt.Println("failed to close the database connection")
			panic(err)
		}
	}()

	if err = runUi(db, false); err != nil {
		fmt.Printf("error running the ui: %v", err.Error())
		panic(err)
	}

}

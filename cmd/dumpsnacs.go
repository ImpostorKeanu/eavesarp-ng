package main

import (
	"errors"
	"fmt"
	"github.com/impostorkeanu/eavesarp-ng/db"
	"github.com/spf13/cobra"
	"os"
	"slices"
)

var (
	dumpSNACSOutputFormats = []string{"csv", "json", "jsonl"}
	dumpSNACSOutputFmt     string
	dumpSNACSCMD           = &cobra.Command{
		Use:     "dump-snacs",
		Short:   "Dump SNAC records from a database file",
		Long:    "Dump SNAC records from a database file",
		Example: "eavesarp-ng dump-snacs -d eavesarp.db -f json",
		Run:     dumpSNACs,
	}
)

func init() {
	dumpSNACSCMD.Flags().StringVarP(&dbFile, "db-file", "d", "eavesarp.db", "Database file")
	dumpSNACSCMD.Flags().StringVarP(&dumpSNACSOutputFmt, "fmt", "f", "jsonl",
		"Output format. One of: [csv, json, jsonl]")
	if err := dumpSNACSCMD.MarkFlagRequired("db-file"); err != nil {
		panic(err)
	} else if slices.Index(dumpSNACSOutputFormats, dumpSNACSOutputFmt) == -1 {
		panic("invalid format; supported formats are: csv, json")
	}
	rootCMD.AddCommand(dumpSNACSCMD)
}

func dumpSNACs(cmd *cobra.Command, args []string) {
	if _, err := os.Stat(dbFile); errors.Is(err, os.ErrNotExist) {
		errExit("database file does not exist", err, 1)
	}
	// open the database
	fmt.Fprintf(os.Stderr, "opening database: %s\n", dbFile)
	dbO, _, err := db.OpenRO(dbFile)
	if err != nil {
		errExit("failed to open database", err, 1)
	}
	// dump the snacs
	os.Stderr.WriteString("dumping snacs to stdout\n\n")
	var n int
	n, err = db.DumpSNACs(dbO, os.Stdout, dumpSNACSOutputFmt)
	if err != nil {
		errExit("failed to dump snacs", err, 1)
	}
	fmt.Fprintf(os.Stderr, "\ndumped %d snacs\n", n)
}

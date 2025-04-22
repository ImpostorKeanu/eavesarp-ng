package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"github.com/impostorkeanu/eavesarp-ng/db"
	"github.com/spf13/cobra"
	"os"
	"slices"
)

var (
	dumpOutputFormats = []string{"csv", "json"}
	dumpOutputFmt     string
	dumpCMD           = &cobra.Command{
		Use:     "dump-snacs",
		Short:   "Dump SNAC records from a database file",
		Long:    "Dump SNAC records from a database file",
		Example: "eavesarp-ng dump-snacs -d eavesarp.db -f json",
		Run:     dumpSNACs,
	}
)

func init() {
	dumpCMD.Flags().StringVarP(&dbFile, "db-file", "d", "eavesarp.db", "Database file")
	dumpCMD.Flags().StringVarP(&dumpOutputFmt, "fmt", "f", "csv", "Output format. One of: [csv, json]")
	if err := dumpCMD.MarkFlagRequired("db-file"); err != nil {
		panic(err)
	} else if slices.Index(dumpOutputFormats, dumpOutputFmt) == -1 {
		panic("invalid format; supported formats are: csv, json")
	}
	rootCMD.AddCommand(dumpCMD)
}

func dumpSNACs(cmd *cobra.Command, args []string) {
	// open the database
	dbO, err := db.OpenDB(dbFile)
	if err != nil {
		panic(err)
	}

	// query for the snacs
	var snacs []db.SNACDumpRecord
	if snacs, err = db.DumpSNACs(dbO); err != nil {
		panic(err)
	} else if len(snacs) == 0 {
		os.Stderr.WriteString("no snacs found\n")
		os.Exit(0)
	}

	switch dumpOutputFmt {
	case "csv":
		// write csv to file
		w := csv.NewWriter(os.Stdout)
		if err = w.Write(db.SNACDumpCSVHeader); err != nil {
			panic(err)
		}
		for _, snac := range snacs {
			if err = w.Write(snac.CSVRow()); err != nil {
				panic(err)
			}
		}
		w.Flush()
	case "json":
		// json marshal and dump output
		var output []byte
		output, err = json.Marshal(snacs)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(output))
	default:
		panic("invalid format; supported formats are: csv, json")
	}
}

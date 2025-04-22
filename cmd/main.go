package main

import (
	"fmt"
	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"
	"os"
)

var (
	dbFile  string // leaving here because it's referenced by multiple commands
	rootCMD = &cobra.Command{
		Use:     "eavesarp-ng",
		Short:   "ARP reconnaissance and SNAC exploitation tool",
		Long:    "",
		Example: startExample,
		Run:     nil,
	}
)

func main() {
	if err := rootCMD.Execute(); err != nil {
		fmt.Printf("failure due to error: %s\n", err.Error())
		os.Exit(1)
	}
}

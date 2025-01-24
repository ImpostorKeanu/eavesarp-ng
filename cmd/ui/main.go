package main

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	"github.com/impostorkeanu/eavesarp-ng/cmd/ui/panes"
	zone "github.com/lrstanley/bubblezone"
	"github.com/spf13/cobra"
	_ "modernc.org/sqlite"
	"os"
	"time"
)

var (
	dbFile    string
	ifaceName string
	rootCmd   = &cobra.Command{
		Use:   "run",
		Short: "ARP reconnaissance tool",
		Run:   start,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&dbFile, "db-file", "d", "eavesarp.sqlite",
		"Database file to use")
	rootCmd.PersistentFlags().StringVarP(&ifaceName, "interface", "i", "",
		"Name of the network interface to monitor")
	if err := rootCmd.MarkPersistentFlagRequired("db-file"); err != nil {
		fmt.Println("db-file is required")
		os.Exit(1)
	}
	if err := rootCmd.MarkPersistentFlagRequired("interface"); err != nil {
		fmt.Println("interface-name is required")
		os.Exit(1)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("failure due to error: %s\n", err.Error())
		os.Exit(1)
	}
}

func initDb(dsn string) (db *sql.DB, err error) {
	db, err = sql.Open("sqlite", dsn)
	if err != nil {
		fmt.Println("error opening the database the database")
		return
	}
	db.SetMaxOpenConns(1)
	// TODO test the connection by pinging the database
	// Apply schema and configurations
	_, err = db.ExecContext(context.Background(), eavesarp_ng.SchemaSql)
	if err != nil {
		fmt.Println("error while applying database schema")
		return
	}
	return
}

func runUi(db *sql.DB, startMainSniffer bool) (err error) {
	zone.NewGlobal()
	selectedArpStyles := convosStyle
	selectedArpStyles.Selected = lipgloss.NewStyle()

	lCh, lPane := panes.NewLogsPane(maxLogLength, maxLogCount)

	ui := model{
		db: db,
		convosTable: table.New(
			table.WithStyles(convosStyle),
			table.WithKeyMap(table.DefaultKeyMap())),
		curConvoTable: table.New(table.WithStyles(selectedArpStyles)),
		//logsViewPort:  viewport.New(0, 0),
		focusedId:     convosTableHeadingId,
		eWriter:       eventWriter{wC: eventsC},
		mainSniff:     startMainSniffer,
		activeAttacks: &ActiveAttacks{},
		convosSpinner: spinner.Model{
			Spinner: spinner.Dot,
			Style:   spinnerStyle,
		},
		convosPoisonPanes: PoisoningPanels{},
		//poisonPanelIds: make(map[string]*panes.PoisonPane),
		logsCh:   lCh,
		logsPane: lPane,
	}
	ui.convosTable.Focus()

	// TODO delete this
	go func() {
		for n := 1; n <= 100; n++ {
			time.Sleep(50 * time.Millisecond)
			lCh <- fmt.Sprintf("event %d", n)
		}
	}()

	// Initialize the ARP table
	//c := getConvosTableContent(ui.db, 100, 0)
	c := getConvosTableContent(&ui)
	if c.err != nil {
		fmt.Println("failed to get initial conversations content")
		return c.err
	}
	ui.doConvoTableContent(c)
	ui.doCurrConvoRow()

	if _, err = tea.NewProgram(ui, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run(); err != nil {
		fmt.Printf("error starting the ui: %v", err.Error())
	}
	return
}

func start(cmd *cobra.Command, args []string) {

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

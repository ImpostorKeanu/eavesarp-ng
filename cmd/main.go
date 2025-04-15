package main

import (
	"fmt"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/impostorkeanu/eavesarp-ng/cmd/misc"
	"github.com/impostorkeanu/eavesarp-ng/cmd/panes"
	"github.com/impostorkeanu/eavesarp-ng/sniff"
	zone "github.com/lrstanley/bubblezone"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
	_ "modernc.org/sqlite"
	"os"
)

var (
	dbFile    string
	ifaceName string
	logFile   string
	logLevel  string
	rootCmd   = &cobra.Command{
		Use:   "run",
		Short: "ARP reconnaissance and SNAC exploitation tool",
		Run:   start,
	}
	poisonPaneLm = sniff.NewConvoLockMap(make(map[string]*panes.PoisonPane))
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&dbFile, "db-file", "d", "eavesarp.sqlite",
		"Database file to use")
	rootCmd.PersistentFlags().StringVarP(&ifaceName, "interface", "i", "",
		"Name of the network interface to monitor")
	rootCmd.PersistentFlags().StringVarP(&logFile, "log-file", "l", "eavesarp.log",
		"Where to send logs")
	rootCmd.PersistentFlags().StringVarP(&logLevel, "log-level", "v", "info",
		"Logging level. Valid values: debug, info, warn, error, dpanic, panic, fatal")
	if err := rootCmd.MarkPersistentFlagRequired("db-file"); err != nil {
		fmt.Println("db-file is required")
		os.Exit(1)
	}
	if err := rootCmd.MarkPersistentFlagRequired("interface"); err != nil {
		fmt.Println("interface is required")
		os.Exit(1)
	}
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("failure due to error: %s\n", err.Error())
		os.Exit(1)
	}
}

func runUi(cfg sniff.Cfg) (err error) {

	zone.NewGlobal()
	selectedArpStyles := convosTableStyle
	selectedArpStyles.Selected = lipgloss.NewStyle()

	lCh, lPane := panes.NewLogsPane(misc.MaxLogLength, misc.MaxLogCount, misc.LogPaneId.String())

	ui := model{
		eCfg: cfg,
		db:   cfg.DB(),
		convosTable: table.New(
			table.WithStyles(convosTableStyle),
			table.WithKeyMap(table.DefaultKeyMap())),
		convoPane: panes.NewCurConvoPane(cfg.DB(), zone.DefaultManager, &activeAttacks, poisonPaneLm, CfgPoisonButtonId),
		focusedId: misc.ConvosPaneId,
		eWriter:   misc.NewEventWriter(lCh),
		convosSpinner: spinner.Model{
			Spinner: spinner.Dot,
			Style:   spinnerStyle,
		},
		logPane:            lPane,
		senderPoisonedChar: senderPoisonedChar,
		snacChar:           snacChar,
		arpSpoofCh:         make(chan sniff.AttackSnacCfg),
		keys:               keys,
		help:               help.New(),
	}
	ui.convosTable.Focus()

	if _, err = tea.NewProgram(ui, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run(); err != nil {
		fmt.Printf("error starting the ui: %v", err.Error())
	}

	return
}

func start(cmd *cobra.Command, args []string) {

	var logOutputs []string
	if logFile != "" {
		logOutputs = append(logOutputs, logFile)
	}
	if logLevel == "" {
		logLevel = "info"
	}

	var logger *zap.Logger
	var err error
	logger, err = sniff.NewLogger(logLevel, logOutputs, logOutputs)
	if err != nil {
		panic(err)
	}

	var cfg sniff.Cfg
	cfg, err = sniff.NewCfg(dbFile, ifaceName, "", logger)
	if err != nil {
		panic(err)
	}

	// close the database connection upon exit
	defer func() {
		db := cfg.DB()
		if db != nil {
			if err := cfg.DB().Close(); err != nil {
				fmt.Println("failed to close the database connection")
				panic(err)
			}
		}
	}()

	if err = runUi(cfg); err != nil {
		fmt.Printf("error running the ui: %v", err.Error())
		panic(err)
	}
}

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
	"io"
	"os"
)

const (
	startExample = "eavesarp-ng -v debug -i eth0"
)

var (
	ifaceName    string
	logFile      string
	dataFile     string
	logLevel     string
	poisonPaneLm *sniff.ConvoLockMap[panes.PoisonPane]
	runCMD       = &cobra.Command{
		Use:     "start",
		Short:   "Start the UI",
		Example: startExample,
		Run:     startUI,
	}
)

func init() {
	runCMD.Flags().StringVarP(&dbFile, "db-file", "d", "eavesarp.db",
		"Database file")
	runCMD.Flags().StringVarP(&ifaceName, "interface", "i", "",
		"Name of the network interface to monitor")
	runCMD.Flags().StringVarP(&logFile, "log-file", "l", "eavesarp-log.jsonl",
		"Where to send logs")
	runCMD.Flags().StringVarP(&logLevel, "log-level", "v", "info",
		"Logging level. Valid values: debug, info, warn, error, panic, fatal")
	runCMD.Flags().StringVarP(&dataFile, "data-file", "y", "eavesarp-data.jsonl",
		"Where to send intercepted data")
	if err := runCMD.MarkFlagRequired("interface"); err != nil {
		fmt.Println("interface is required")
		os.Exit(1)
	}

	rootCMD.AddCommand(runCMD)
}

func run(cfg sniff.Cfg) (err error) {

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

func startUI(cmd *cobra.Command, args []string) {

	poisonPaneLm = sniff.NewConvoLockMap(make(map[string]*panes.PoisonPane))
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
		fmt.Printf("error initializing logger: %v", err.Error())
		panic(err)
	}

	var dataW io.Writer
	if dataW, err = os.OpenFile(dataFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666); err != nil {
		fmt.Printf("error opening data file for writing: %v", err.Error())
		panic(err)
	}

	var cfg sniff.Cfg
	cfg, err = sniff.NewCfg(nil, dbFile, ifaceName, "", logger, dataW,
		sniff.LocalUDPProxyServerAddrOpt(""),
		sniff.LocalTCPProxyServerAddrOpt(""))
	if err != nil {
		fmt.Printf("error initializing eavesarp config: %v", err.Error())
		panic(err)
	}
	defer cfg.Shutdown()

	if err = run(cfg); err != nil {
		fmt.Printf("error running the ui: %v", err.Error())
		panic(err)
	}
}

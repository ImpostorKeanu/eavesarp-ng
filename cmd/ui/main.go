package main

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	zone "github.com/lrstanley/bubblezone"
	"math"
	_ "modernc.org/sqlite"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

var (
	panelStyle = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), true, true, true, true).
		BorderForeground(lipgloss.Color("240"))
	centerStyle             = lipgloss.NewStyle().AlignHorizontal(lipgloss.Center)
	selectedPaneBorderColor = lipgloss.Color("248")
	arpTableStyles          table.Styles
	eventsC                 = make(chan string)
)

const (
	maxLogCount  = 1000
	maxLogLength = 2000
)

func init() {
	arpTableStyles = table.DefaultStyles()
	arpTableStyles.Header = arpTableStyles.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true).
		PaddingLeft(1)
	arpTableStyles.Cell.PaddingLeft(1)
	arpTableStyles.Selected = arpTableStyles.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
}

type (
	model struct {
		db               *sql.DB
		arpTable         table.Model
		curArpRowSenders map[int]string
		curArpRow        arpRow
		curArpTable      table.Model
		curArpContent    *selectedArpTableContent

		logViewPort viewport.Model

		uiHeight, uiWidth       int
		rightHeight, rightWidth int
		focusedId               paneId
		events                  []string
		eWriter                 eventWriter
	}

	arpRow struct {
		index    int
		isSnac   bool
		senderIp string
		targetIp string
		arpCount int
	}

	logEvent string
)

func newArpTableRow(r table.Row) (_ arpRow, err error) {
	var ind, arpCount int
	if ind, err = strconv.Atoi(r[0]); err != nil {
		return
	} else if arpCount, err = strconv.Atoi(r[4]); err != nil {
		return
	}
	return arpRow{ind, r[1] != "", r[2], r[3], arpCount}, err
}

func (m model) Init() tea.Cmd {
	return tea.Batch(
		emitEvent,
		func() tea.Msg {
			return getArpTableContent(m.db, 100, 0)
		},
	)
}

func emitEvent() tea.Msg {
	return logEvent(<-eventsC)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		// This type is supplied when:
		//
		// - The model is being initialized
		// - The terminal window size has changed
		//
		// Since it's supplied as the model is initialized,
		// this logic will also be accessed during initial
		// rendering.

		m.doResize(msg)

	case arpTableContent:

		if msg.err != nil {
			_, err := m.eWriter.WriteStringf("failed update arp table content: %v", msg.err.Error())
			if err != nil {
				m.eWriter.WriteString("failed to call WriteStringf while reporting error")
				panic(err)
			}
		} else {
			m.curArpRowSenders = msg.rowSenders
			m.doArpTableContent(msg)
		}

		return m, func() tea.Msg {
			// Periodically update the ARP table
			// TODO we may want to make the update frequency configurable
			time.Sleep(2 * time.Second)
			return getArpTableContent(m.db, 100, 0)
		}

	case logEvent:

		s := string(msg)

		// Trim length of the log event
		if len(s) > maxLogLength {
			s = s[:maxLogLength-1]
		}

		// Trim 10% of logs when the maximum has been met to
		// make room for new events
		if len(m.events) >= maxLogCount {
			l := len(m.events)
			m.events = slices.Delete(m.events, l-(l/10), l-1)
		}

		// Capture the event and write to the viewport
		m.events = append(m.events, s)
		m.logViewPort.SetContent(strings.Join(m.events, "\n"))

		// Return the model and start a new process to catch the
		// next event, which is handled by the event loop managed
		// by charmbracelet.
		return m, emitEvent

	case tea.MouseMsg:

		if msg.Action != tea.MouseActionRelease || msg.Button != tea.MouseButtonLeft {
			return m, nil
		}

		//===========================================
		// CHANGE FOCUSED PANES BASED ON HEADER CLICK
		//===========================================

		if m.focusedId != logViewPortId && zone.Get(logViewPortId.String()).InBounds(msg) {
			m.focusedId = logViewPortId
		} else if m.focusedId != arpTableId && zone.Get(arpTableId.String()).InBounds(msg) {
			m.focusedId = arpTableId
		} else if m.focusedId != attacksViewPortId && zone.Get(attacksViewPortId.String()).InBounds(msg) {
			m.focusedId = attacksViewPortId
		} else if m.focusedId != curArpTableId && zone.Get(curArpTableId.String()).InBounds(msg) {
			m.focusedId = curArpTableId
		}

	case tea.KeyMsg:

		//====================
		// STANDARD KEYSTROKES
		//====================

		switch msg.String() {
		case "q", "ctrl+c":
			// TODO kill ongoing routines
			return m, tea.Quit
		}

		switch m.focusedId {
		case arpTableId:

			//=====================
			// ARP TABLE KEYSTROKES
			//=====================

			switch msg.String() {
			case "up", "k":
				if m.arpTable.Cursor() == 0 {
					m.arpTable.GotoBottom()
				} else {
					m.arpTable.MoveUp(1)
				}
				m.doCurrArpTableRow()
			case "down", "j":
				if m.arpTable.Cursor() == len(m.arpTable.Rows())-1 {
					m.arpTable.GotoTop()
				} else {
					m.arpTable.MoveDown(1)
				}
				m.doCurrArpTableRow()
			case "ctrl+shift+up":
				m.focusedId = curArpTableId
			case "ctrl+shift+right":
				m.focusedId = attacksViewPortId
			case "ctrl+shift+down":
				m.focusedId = logViewPortId
			case "q", "ctrl+c":
				return m, tea.Quit
			}
			return m, nil

		case curArpTableId:

			switch msg.String() {
			case "ctrl+shift+left":
				m.focusedId = arpTableId
			case "ctrl+shift+down":
				m.focusedId = attacksViewPortId
			case "ctrl+shift+up":
				m.focusedId = logViewPortId
			}

		case attacksViewPortId:

			switch msg.String() {
			case "ctrl+shift+up":
				m.focusedId = curArpTableId
			case "ctrl+shift+down":
				m.focusedId = logViewPortId
			case "ctrl+shift+left":
				m.focusedId = arpTableId
			}

		case logViewPortId:

			switch msg.String() {
			case "down":
				m.logViewPort.LineDown(1)
			case "up":
				m.logViewPort.LineUp(1)
			case "ctrl+shift+left":
				m.focusedId = arpTableId
			case "ctrl+shift+up":
				m.focusedId = attacksViewPortId
			case "ctrl+shift+down":
				m.focusedId = curArpTableId
			}

		}

	}

	return m, nil
}

func (m model) View() string {

	//===========================
	// CURRENT ARP TABLE ROW PANE
	//===========================

	m.curArpTable.SetWidth(m.rightWidth)
	m.curArpTable.SetHeight(m.rightHeight)

	//================
	// REMAINING PANES
	//================

	rightPaneStyle := panelStyle
	rightPaneStyle = rightPaneStyle.Width(m.rightWidth).Height(m.rightHeight)

	// Logging pane will be shorter than the other two right-hand panes
	w, h := lipgloss.Size(rightPaneStyle.Render())

	logsHeight := m.uiHeight - (h * 2)
	logsPaneStyle := rightPaneStyle
	logsPaneStyle = logsPaneStyle.Height(logsHeight)

	m.logViewPort.Height = m.uiHeight - (h * 2)
	m.logViewPort.Width = w

	if m.logViewPort.YOffset == 0 && m.logViewPort.Height > 0 {
		// Scroll to the bottom of the logs viewport
		m.logViewPort.GotoBottom()
	}

	centerRightHeadingStyle := centerStyle
	centerRightHeadingStyle = centerRightHeadingStyle.Width(m.rightWidth)

	arpTableStyle := panelStyle
	selectedArpTableStyle := panelStyle
	attacksPanelStyle := panelStyle
	logViewPortStyle := panelStyle

	//==================================
	// BRIGHTEN BORDER FOR SELECTED PANE
	//==================================

	switch m.focusedId {
	case arpTableId:
		arpTableStyle = arpTableStyle.BorderForeground(selectedPaneBorderColor)
	case curArpTableId:
		selectedArpTableStyle = selectedArpTableStyle.BorderForeground(selectedPaneBorderColor)
	case attacksViewPortId:
		attacksPanelStyle = attacksPanelStyle.BorderForeground(selectedPaneBorderColor)
	case logViewPortId:
		logViewPortStyle = logViewPortStyle.BorderForeground(selectedPaneBorderColor)
	}

	m.logViewPort.Style = logViewPortStyle
	attacksPanelStyle = attacksPanelStyle.Width(m.rightWidth).Height(m.rightHeight)

	leftPane := lipgloss.JoinVertical(lipgloss.Center,
		zone.Mark(arpTableId.String(), centerStyle.Render("ARP Table")),
		arpTableStyle.Render(lipgloss.JoinHorizontal(lipgloss.Center, m.arpTable.View())))

	rightPane := lipgloss.JoinVertical(lipgloss.Left,
		zone.Mark(curArpTableId.String(), centerRightHeadingStyle.Render("Selected ARP Row")),
		selectedArpTableStyle.Render(m.curArpTable.View()),
		zone.Mark(attacksViewPortId.String(), centerRightHeadingStyle.Render("Attacks")),
		attacksPanelStyle.Render("stuff and things"),
		zone.Mark(logViewPortId.String(), centerRightHeadingStyle.Render("Logs")),
		m.logViewPort.View())

	return zone.Scan(lipgloss.JoinHorizontal(lipgloss.Left, leftPane, rightPane))
}

func (m *model) doResize(msg tea.WindowSizeMsg) {
	m.uiHeight = int(math.Round(float64(msg.Height) * .93))
	m.uiWidth = int(math.Round(float64(msg.Width) * .93))
	m.arpTable.SetHeight(m.uiHeight)
	m.rightWidth = m.uiWidth / 2
	m.rightHeight = m.uiHeight / 3
	m.doCurrArpTableRow()
}

func (m *model) doCurrArpTableRow() {
	// Copy the currently selected row and insert the current sender IP,
	// which is needed to query the content for the currently selected
	// row
	selectedRow := make(table.Row, len(m.arpTable.SelectedRow()))
	copy(selectedRow, m.arpTable.SelectedRow())
	if strings.HasSuffix(selectedRow[2], "↖") {
		selectedRow[2] = m.curArpRowSenders[m.arpTable.Cursor()]
	}

	var err error
	if m.curArpRow, err = newArpTableRow(selectedRow); err != nil {
		eventsC <- fmt.Sprintf("failed to generate table for selected arp row: %v", err.Error())
		return
	}

	// Get content for the selected ARP table
	buff := getSelectedArpTableContent(m)
	if buff.err != nil {
		_, err = m.eWriter.WriteStringf("failed to get selected arp table content: %v", err.Error())
		if err != nil {
			m.eWriter.WriteString("failed to write error to log pane")
			panic(err)
		}
	} else {
		m.curArpContent = &buff
		m.curArpTable.SetColumns(buff.cols)
		m.curArpTable.SetRows(buff.rows)
	}
}

func (m *model) doArpTableContent(c arpTableContent) {
	if c.err != nil {
		// TODO
		panic(c.err)
	}
	m.arpTable.SetColumns(c.cols)
	m.arpTable.SetRows(c.rows)
	//if m.uiHeight != m.arpTable.Height() {
	//	m.arpTable.SetHeight(m.uiHeight)
	//}
	m.doCurrArpTableRow()
}

func main() {
	zone.NewGlobal()

	db, err := sql.Open("sqlite", "/home/archangel/git/eavesarp-ng/junk.sqlite")
	if err != nil {
		println("error", err.Error())
		os.Exit(1)
	}

	eWriter := eventWriter{wC: eventsC}

	go eavesarp_ng.MainSniff(db, "enp13s0", eWriter)
	time.Sleep(1 * time.Second)

	// TODO test the connection by pinging the database
	db.SetMaxOpenConns(1)

	// Apply schema and configurations
	if _, err = db.ExecContext(context.Background(), eavesarp_ng.SchemaSql); err != nil {
		// TODO
		println("error", err.Error())
		os.Exit(1)
	}

	selectedArpStyles := arpTableStyles
	selectedArpStyles.Selected = lipgloss.NewStyle()

	ui := model{
		db:          db,
		arpTable:    table.New(table.WithStyles(arpTableStyles)),
		curArpTable: table.New(table.WithStyles(selectedArpStyles)),
		logViewPort: viewport.New(0, 0),
		focusedId:   arpTableId,
		eWriter:     eWriter,
	}
	ui.logViewPort.Style = panelStyle

	// Initialize the ARP table
	c := getArpTableContent(ui.db, 100, 0)
	if c.err != nil {
		// TODO
		panic(c.err)
	}
	ui.doArpTableContent(c)
	ui.doCurrArpTableRow()

	if _, err := tea.NewProgram(ui, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run(); err != nil {
		panic(err)
	}
}

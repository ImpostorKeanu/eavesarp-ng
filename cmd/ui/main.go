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

	eventsC = make(chan string)
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

const (
	arpTableId         panelId = "arpTable"
	selectedArpTableId panelId = "selectedArpTable"
	logPaneId          panelId = "logViewPort"
	attacksPaneId      panelId = "attacksViewPort"
)

func (p panelId) String() string {
	return string(p)
}

func (p panelId) Int() int {
	switch p {
	case arpTableId:
		return 0
	case selectedArpTableId:
		return 1
	case logPaneId:
		return 2
	case attacksPaneId:
		return 3
	default:
		panic("invalid panelId")
	}
}

func panelIdFromInt(i int, direction string) (p panelId) {
	if direction == "forward" {
		if i == 3 {
			i = 0
		} else {
			i++
		}
	} else if direction == "backward" {
		if i == 0 {
			i = 3
		} else {
			i--
		}
	} else {
		panic("invalid integer for direction")
	}

	switch i {
	case 0:
		return arpTableId
	case 1:
		return selectedArpTableId
	case 2:
		return logPaneId
	case 3:
		return attacksPaneId
	default:
		panic("invalid panelId integer")
	}
}

type (
	panelId string

	model struct {
		db            *sql.DB
		arpTable      table.Model
		curArpRow     arpRow
		curArpTable   table.Model
		curArpContent *selectedArpTableContent

		logViewPort viewport.Model

		uiHeight, uiWidth       int
		rightHeight, rightWidth int
		focusedId               panelId
		events                  []string
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
		emitTestEvents,
	)
}

func emitEvent() tea.Msg {
	return logEvent(<-eventsC)
}

func emitTestEvents() tea.Msg {
	time.Sleep(2 * time.Second)
	for x := 0; x < 10; x++ {
		eventsC <- fmt.Sprintf("event %d", x)
		time.Sleep(500 * time.Millisecond)
	}
	return ""
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

		m.doArpTableContent(msg)

	case logEvent:

		m.events = append(m.events, string(msg))
		m.logViewPort.SetContent(strings.Join(m.events, "\n"))
		return m, emitEvent

	case tea.MouseMsg:

		if msg.Action != tea.MouseActionRelease || msg.Button != tea.MouseButtonLeft {
			return m, nil
		}

		//===========================================
		// CHANGE FOCUSED PANES BASED ON HEADER CLICK
		//===========================================

		if m.focusedId != logPaneId && zone.Get(logPaneId.String()).InBounds(msg) {
			m.focusedId = logPaneId
		} else if m.focusedId != arpTableId && zone.Get(arpTableId.String()).InBounds(msg) {
			m.focusedId = arpTableId
		} else if m.focusedId != attacksPaneId && zone.Get(attacksPaneId.String()).InBounds(msg) {
			m.focusedId = attacksPaneId
		} else if m.focusedId != selectedArpTableId && zone.Get(selectedArpTableId.String()).InBounds(msg) {
			m.focusedId = selectedArpTableId
		}

	case tea.KeyMsg:

		//====================
		// STANDARD KEYSTROKES
		//====================

		switch msg.String() {
		case "ctrl+shift+right":
			// Move forward a panel
			m.focusedId = panelIdFromInt(m.focusedId.Int(), "forward")
		case "ctrl+shift+left":
			// Move back a panel
			m.focusedId = panelIdFromInt(m.focusedId.Int(), "backward")
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
				m.doCurrentArpTableRow()
			case "down", "j":
				if m.arpTable.Cursor() == len(m.arpTable.Rows())-1 {
					m.arpTable.GotoTop()
				} else {
					m.arpTable.MoveDown(1)
				}
				m.doCurrentArpTableRow()
			case "q", "ctrl+c":
				return m, tea.Quit
			}
			return m, nil

		case logPaneId:

			//====================
			// LOG PANE KEYSTROKES
			//====================

			switch msg.String() {
			case "down":
				m.logViewPort.LineDown(1)
			case "up":
				m.logViewPort.LineUp(1)
			}

		}

	}

	return m, nil
}

func (m model) View() string {

	//===============
	// ARP TABLE PANE
	//===============

	m.arpTable.SetHeight(m.uiHeight - 1)

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

	m.logViewPort.Height = (m.uiHeight - (h * 2)) - 1
	m.logViewPort.Width = w

	if m.logViewPort.YOffset == 0 {
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
	case selectedArpTableId:
		selectedArpTableStyle = selectedArpTableStyle.BorderForeground(selectedPaneBorderColor)
	case attacksPaneId:
		attacksPanelStyle = attacksPanelStyle.BorderForeground(selectedPaneBorderColor)
	case logPaneId:
		logViewPortStyle = logViewPortStyle.BorderForeground(selectedPaneBorderColor)
	}

	m.logViewPort.Style = logViewPortStyle
	attacksPanelStyle = attacksPanelStyle.Width(m.rightWidth).Height(m.rightHeight)

	leftPane := lipgloss.JoinVertical(lipgloss.Center,
		zone.Mark(arpTableId.String(), centerStyle.Render("ARP Table")),
		arpTableStyle.Render(lipgloss.JoinHorizontal(lipgloss.Center, m.arpTable.View())))

	rightPane := lipgloss.JoinVertical(lipgloss.Left,
		zone.Mark(selectedArpTableId.String(), centerRightHeadingStyle.Render("Selected ARP Row")),
		selectedArpTableStyle.Render(m.curArpTable.View()),
		zone.Mark(attacksPaneId.String(), centerRightHeadingStyle.Render("Attacks")),
		attacksPanelStyle.Render("stuff and things"),
		zone.Mark(logPaneId.String(), centerRightHeadingStyle.Render("Logs")),
		m.logViewPort.View())

	return zone.Scan(lipgloss.JoinHorizontal(lipgloss.Left, leftPane, rightPane))
}

func (m *model) doResize(msg tea.WindowSizeMsg) {
	m.uiHeight = int(math.Round(float64(msg.Height) * .93))
	m.uiWidth = int(math.Round(float64(msg.Width) * .93))
	m.rightWidth = m.uiWidth / 2
	m.rightHeight = m.uiHeight / 3
	m.doCurrentArpTableRow()
}

func (m *model) doCurrentArpTableRow() {
	// TODO handle this error
	m.curArpRow, _ = newArpTableRow(m.arpTable.SelectedRow())
	buff := getSelectedArpTableContent(m.db, m)
	m.curArpContent = &buff
	m.curArpTable.SetColumns(buff.cols)
	m.curArpTable.SetRows(buff.rows)
}

func (m *model) doArpTableContent(c arpTableContent) {
	if c.err != nil {
		// TODO
		panic(c.err)
	}
	m.arpTable.SetColumns(c.cols)
	m.arpTable.SetRows(c.rows)
	m.doCurrentArpTableRow()
}

func (m *model) doArpTableKeyPress(k string) (tea.Model, tea.Cmd) {
	switch k {
	case "up", "k":
		if m.arpTable.Cursor() == 0 {
			m.arpTable.GotoBottom()
		} else {
			m.arpTable.MoveUp(1)
		}
		m.doCurrentArpTableRow()
	case "down", "j":
		if m.arpTable.Cursor() == len(m.arpTable.Rows())-1 {
			m.arpTable.GotoTop()
		} else {
			m.arpTable.MoveDown(1)
		}
		m.doCurrentArpTableRow()
	case "q", "ctrl+c":
		return m, tea.Quit
	}
	return nil, nil
}

func main() {
	zone.NewGlobal()

	db, err := sql.Open("sqlite", "/home/archangel/git/eavesarp-ng/junk.sqlite")
	if err != nil {
		println("error", err.Error())
		os.Exit(1)
	}

	// TODO test the connection by pinging the database
	//db.SetMaxOpenConns(3)
	db.SetConnMaxLifetime(0)

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
	}
	ui.logViewPort.Style = panelStyle

	c := getArpTableContent(ui.db, 100, 0)
	if c.err != nil {
		// TODO
		panic(c.err)
	}
	ui.doArpTableContent(c)

	if _, err := tea.NewProgram(ui, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run(); err != nil {
		panic(err)
	}

}

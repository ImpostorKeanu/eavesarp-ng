package main

import (
	"context"
	"database/sql"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	zone "github.com/lrstanley/bubblezone"
	"math"
	_ "modernc.org/sqlite"
	"os"
	"strconv"
)

var (
	panelStyle = lipgloss.NewStyle().
		Border(lipgloss.NormalBorder(), true, true, true, true)
	arpTableStyles table.Styles
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
	arpTableId = "arpTable"
)

type (
	model struct {
		db        *sql.DB
		arpTable  table.Model
		curArpRow arpRow

		curArpTable   table.Model
		curArpContent *selectedArpTableContent

		uiHeight, uiWidth       int
		rightHeight, rightWidth int

		focusedId string
	}

	arpRow struct {
		index    int
		isSnac   bool
		senderIp string
		targetIp string
		arpCount int
	}
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
	c := getArpTableContent(m.db, 100, 0)
	if c.err != nil {
		// TODO
		panic(c.err)
	}
	return func() tea.Msg {
		return c
	}
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

	case tea.KeyMsg:

		// TODO derive method of tracking which pane has focus so that we can handle
		//  events for them
		var tbl *table.Model
		switch m.focusedId {
		case arpTableId:
			tbl = &m.arpTable
		}

		if tbl != nil {
			if m, cmd := m.doArpTableKeyPress(msg.String()); cmd != nil && m != nil {
				return m, cmd
			}
		}

	}

	return m, nil
}

func (m model) View() string {

	//===============
	// ARP TABLE PANE
	//===============

	m.arpTable.SetHeight(m.uiHeight)

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

	//m.selectedArpPane.style = rightPaneStyle
	//m.attacksPane.style = rightPaneStyle

	// Logging pane will be shorter than the other two right-hand panes
	_, h := lipgloss.Size(rightPaneStyle.Render())
	logsPaneStyle := rightPaneStyle
	logsPaneStyle = logsPaneStyle.Height(m.uiHeight - (h * 2))

	return zone.Scan(lipgloss.JoinHorizontal(lipgloss.Left,
		panelStyle.Render(m.arpTable.View()),
		lipgloss.JoinVertical(lipgloss.Left,
			panelStyle.Render(m.curArpTable.View()),
			rightPaneStyle.Render("Attacks"),
			logsPaneStyle.Render("Logs"))))
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

	//for n := 0; n < 90; n++ {
	//	c.rows = append(c.rows, table.Row{"x", "x", "x", "x", "x"})
	//}

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
		focusedId:   arpTableId,
	}

	if _, err := tea.NewProgram(ui, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run(); err != nil {
		panic(err)
	}

}

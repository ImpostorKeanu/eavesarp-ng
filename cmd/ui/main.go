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
	pane struct {
		title string
		style lipgloss.Style
	}

	model struct {
		db                                 *sql.DB
		selectedArpPane                    pane
		attacksPane                        pane
		logsPane                           pane
		arpTable                           arpTable
		selectedArpTable                   table.Model
		selectedTargetId, selectedSenderId int
		height, width                      int
		focusedId                          string
	}

	arpTableRowOffset int

	arpTableRow struct {
		index    int
		isSnac   bool
		senderIp string
		targetIp string
		arpCount int
	}

	arpTable struct {
		table.Model
		selectedArpRow arpTableRow
	}
)

func newArpTableRow(r table.Row) (_ arpTableRow, err error) {
	var ind, arpCount int
	if ind, err = strconv.Atoi(r[0]); err != nil {
		return
	} else if arpCount, err = strconv.Atoi(r[4]); err != nil {
		return
	}
	return arpTableRow{ind, r[1] != "", r[2], r[3], arpCount}, err
}

func (p pane) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return p, nil
}

func (p pane) View() string {
	return p.style.Render(p.title)
}

func (p pane) Init() tea.Cmd {
	return nil
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

		var tbl *arpTable
		switch m.focusedId {
		case arpTableId:
			tbl = &m.arpTable
		}

		if tbl != nil {
			if m, cmd := m.doTableKey(msg.String()); cmd != nil && m != nil {
				return m, cmd
			}
		}

	}

	return m, nil
}

func (m model) View() string {
	m.arpTable.SetHeight(m.height)
	return zone.Scan(lipgloss.JoinHorizontal(lipgloss.Left,
		panelStyle.Render(m.arpTable.View()),
		lipgloss.JoinVertical(lipgloss.Left, m.selectedArpPane.View(), m.attacksPane.View(), m.logsPane.View())))
}

func (m *model) doResize(msg tea.WindowSizeMsg) {
	m.height = int(math.Round(float64(msg.Height) * .90))
	m.width = int(math.Round(float64(msg.Width) * .90))
	m.arpTable.SetHeight(m.height)

	w := m.width / 2
	h := m.height / 3

	rightStyle := panelStyle
	rightStyle = rightStyle.Width(w).Height(h)

	m.selectedArpPane.style = rightStyle
	m.attacksPane.style = rightStyle

	// Logging pane will be shorter than the other two right-hand panes
	_, h = lipgloss.Size(m.selectedArpPane.View())
	m.logsPane.style = rightStyle.Height(m.height - (h * 2))
}

func (m *model) doArpTableContent(c arpTableContent) {
	if c.err != nil {
		// TODO
		panic(c.err)
	}
	m.arpTable.SetColumns(c.cols)
	m.arpTable.SetRows(c.rows)
	// TODO handle this error
	m.arpTable.selectedArpRow, _ = newArpTableRow(m.arpTable.SelectedRow())
}

func (m *model) doTableKey(k string) (tea.Model, tea.Cmd) {
	switch k {
	case "up", "k":
		if m.arpTable.Cursor() == 0 {
			m.arpTable.GotoBottom()
		} else {
			m.arpTable.MoveUp(1)
		}
		// TODO handle this error
		m.arpTable.selectedArpRow, _ = newArpTableRow(m.arpTable.SelectedRow())
	case "down", "j":
		if m.arpTable.Cursor() == len(m.arpTable.Rows())-1 {
			m.arpTable.GotoTop()
		} else {
			m.arpTable.MoveDown(1)
		}
		// TODO handle this error
		m.arpTable.selectedArpRow, _ = newArpTableRow(m.arpTable.SelectedRow())
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

	//c := getArpTableContent(db)
	//if c.err != nil {
	//	// TODO
	//	panic(c.err)
	//}

	ui := model{
		db:              db,
		selectedArpPane: pane{title: "Host Information"},
		attacksPane:     pane{title: "Attacks"},
		logsPane:        pane{title: "Logs"},
		arpTable:        arpTable{Model: table.New(table.WithStyles(arpTableStyles))},
		focusedId:       arpTableId,
	}

	if _, err := tea.NewProgram(ui, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run(); err != nil {
		panic(err)
	}

}

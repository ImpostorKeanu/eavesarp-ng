package main

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/enescakir/emoji"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	_ "modernc.org/sqlite"
	"os"
)

const (
	mainTblQuery = `
SELECT sender.id AS sender_ip_id,
       sender.value AS sender_ip_value,
       target.id AS target_ip_id,
       target.value AS target_ip_value,
       count AS arp_count,
       (target.arp_resolved AND target.mac_id IS NULL) AS snac
FROM arp_count
    INNER JOIN ip AS sender ON arp_count.sender_ip_id = sender.id
    INNER JOIN ip AS target ON arp_count.target_ip_id = target.id
ORDER BY
    snac DESC,
    arp_count.count DESC`
)

type model struct {
	table table.Model
	db    *sql.DB
}

type TblContent struct {
	cols []table.Column
	rows []table.Row
	err  error
}

func GetTableContent(db *sql.DB) (content TblContent) {
	rows, err := db.Query(mainTblQuery)
	if err != nil {
		content.err = err
		return
	}

	// Variables to track information about row content
	// - these are used to format table columns later
	var senderIpWidth, targetIpWidth int
	var snacsSeen bool
	arpCountHeader := "ARP #"
	arpCountWidth := len(arpCountHeader)
	var lastSenderIp string

	defer rows.Close()
	for rows.Next() {

		//====================
		// HANDLE DATABASE ROW
		//====================

		// Variables to hold data retrieved from the db
		var sender, target eavesarp_ng.Ip
		var arpCount int
		var hasSnac bool
		var senderChanged bool

		// Get data from the sql row
		err = rows.Scan(&sender.Id, &sender.Value,
			&target.Id, &target.Value,
			&arpCount, &hasSnac)
		if err != nil {
			content.err = err
			return
		}

		// Determine if the SNAC column should be displayed
		if hasSnac && !snacsSeen {
			snacsSeen = true
		}

		//===================
		// PREPARE ROW VALUES
		//===================

		// Maximum sender and target IP column widths
		if len(sender.Value) > senderIpWidth {
			senderIpWidth = len(sender.Value)
		}
		if lastSenderIp != sender.Value {
			senderChanged = true
			lastSenderIp = sender.Value
		}
		if len(target.Value) > targetIpWidth {
			targetIpWidth = len(target.Value)
		}

		// ARP count column width
		arpCountValue := fmt.Sprintf("%d", arpCount)
		if len(arpCountValue) > arpCountWidth {
			arpCountWidth = len(arpCountValue)
		}

		//======================================
		// CONSTRUCT AND CAPTURE THE CURRENT ROW
		//======================================

		var tRow table.Row

		// Include the snacs column if they've been seen regardless
		// if the row represents a snac
		if snacsSeen {
			if hasSnac {
				tRow = append(tRow, string(emoji.DirectHit))
			} else {
				tRow = append(tRow, "")
			}
		}

		if senderChanged {
			tRow = append(tRow, sender.Value)
		} else {
			tRow = append(tRow, "")
		}

		content.rows = append(content.rows, append(tRow, target.Value, arpCountValue))
	}

	//======================
	// PREPARE TABLE COLUMNS
	//======================

	// Include the snacs column if snacs were seen
	if snacsSeen {
		content.cols = append(content.cols, table.Column{"", 2})
	}

	// Add remaining table columns
	content.cols = append(content.cols,
		table.Column{"Sender", senderIpWidth},
		table.Column{"Target", targetIpWidth},
		table.Column{"ARP #", arpCountWidth})

	return
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case TblContent:
		if msg.err != nil {
			// TODO
			panic(msg.err)
		}
		m.table.SetRows(msg.rows)
		m.table.SetColumns(msg.cols)
		m.table, cmd = m.table.Update(msg)
		return m, cmd
	case tea.KeyMsg:
		switch msg.String() {
		case "esc":
			if m.table.Focused() {
				m.table.Blur()
			} else {
				m.table.Focus()
			}
		case "q", "ctrl+c":
			return m, tea.Quit
		case "up", "k":
			if m.table.Cursor() == 0 {
				m.table.GotoBottom()
			} else {
				m.table.MoveUp(1)
			}
		case "down", "j":
			if m.table.Cursor() == len(m.table.Rows())-1 {
				m.table.GotoTop()
			} else {
				m.table.MoveDown(1)
			}
		case "enter":
			return m, tea.Batch(
				tea.Printf("Let's go to %s!", m.table.SelectedRow()[1]),
			)
		}
	}
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

var baseStyle = lipgloss.NewStyle().
	BorderStyle(lipgloss.NormalBorder()).
	BorderForeground(lipgloss.Color("240"))

func (m model) View() string {
	return baseStyle.Render(m.table.View()) + "\n" + m.table.HelpView()
}

func main() {
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

	c := GetTableContent(db)
	if c.err != nil {
		// TODO
		panic(c.err)
	}

	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(true).
		PaddingLeft(1)
	s.Cell.PaddingLeft(1)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)

	m := model{
		//table: table.New(table.WithColumns(c.cols), table.WithRows(c.rows), table.WithStyles(s)),
		table: table.New(table.WithColumns(c.cols), table.WithRows(c.rows), table.WithStyles(s)),
		db:    db}

	if _, err = tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		println("error", err.Error())
		os.Exit(1)
	}
}

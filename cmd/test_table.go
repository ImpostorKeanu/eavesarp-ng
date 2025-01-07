package main

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	_ "modernc.org/sqlite"
	"os"
)

type model struct {
	table table.Model
}

func (m model) Init() tea.Cmd { return nil }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
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
	return baseStyle.Render(m.table.View()) + "\n"
}

func main() {
	db, err := sql.Open("sqlite", "/home/archangel/git/eavesarp-ng/junk.sqlite")
	if err != nil {
		println("error", err.Error())
		os.Exit(1)
	}

	// TODO test the connection by pinging the database
	db.SetMaxOpenConns(3)
	db.SetConnMaxLifetime(0)

	// Apply schema and configurations
	if _, err = db.ExecContext(context.Background(), eavesarp_ng.SchemaSql); err != nil {
		// TODO
		println("error", err.Error())
		os.Exit(1)
	}

	cols := []table.Column{
		{"IP", 17},
		{"Discovery Method", 20},
		{"ARP Resolved", 15},
		{"PTR Resolved", 15},
	}

	var tRows []table.Row
	rows, err := db.Query(`
SELECT ip.value,ip.disc_meth,ip.arp_resolved,ip.ptr_resolved FROM ip

SELECT * FROM (
	SELECT sender.id, sender.value, target.id, target.value, (target.arp_resolved=TRUE AND target.mac_id IS NULL) AS SNAC, count FROM arp_count
	INNER JOIN ip AS sender ON arp_count.sender_ip_id = sender.id
    INNER JOIN ip AS target ON arp_count.target_ip_id = target.id
    ORDER BY arp_count.count DESC
);
`)
	if err != nil {
		panic(err)
	}
	for rows.Next() {
		var ip eavesarp_ng.Ip
		if err = rows.Scan(&ip.Value, &ip.DiscMethod, &ip.ArpResolved, &ip.PtrResolved); err != nil {
			panic(err)
		}
		tRows = append(tRows, table.Row{ip.Value, string(ip.DiscMethod), fmt.Sprintf("%v", ip.ArpResolved), fmt.Sprintf("%v", ip.PtrResolved)})
	}

	tbl := table.New(
		table.WithColumns(cols),
		table.WithRows(tRows))
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	tbl.SetStyles(s)

	m := model{tbl}
	if _, err = tea.NewProgram(m).Run(); err != nil {
		println("error", err.Error())
		os.Exit(1)
	}
}

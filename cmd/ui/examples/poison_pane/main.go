package main

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/impostorkeanu/eavesarp-ng/cmd/ui/panes"
	zone "github.com/lrstanley/bubblezone"
)

type model struct {
	pane panes.PoisonPane
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m.pane.Update(msg)
}

func (m model) View() string {
	return zone.Scan(m.pane.View())
}

func (m model) Init() tea.Cmd {
	return nil
}

func main() {
	zone.NewGlobal()
	p := panes.NewPoison(zone.DefaultManager)
	p.Style = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), true, true, true, true)
	p.height = 10
	p.width = 70
	if _, err := tea.NewProgram(model{p}, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run(); err != nil {
		fmt.Printf("error starting the ui: %v", err.Error())
	}
}

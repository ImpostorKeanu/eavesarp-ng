package main

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/impostorkeanu/eavesarp-ng/cmd/ui/poison_panel"
	zone "github.com/lrstanley/bubblezone"
)

type model struct {
	panel poison_panel.PoisonPanel
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m.panel.Update(msg)
}

func (m model) View() string {
	return zone.Scan(m.panel.View())
}

func (m model) Init() tea.Cmd {
	return nil
}

func main() {
	zone.NewGlobal()
	p := poison_panel.New(zone.DefaultManager)
	p.Style = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), true, true, true, true)
	p.Height = 10
	p.Width = 70
	if _, err := tea.NewProgram(model{p}, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run(); err != nil {
		fmt.Printf("error starting the ui: %v", err.Error())
	}
}

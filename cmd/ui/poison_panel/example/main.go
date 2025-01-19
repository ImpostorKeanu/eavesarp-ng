package main

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func main() {
	p := poison_panel.New()
	p.Style = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), true, true, true, true)
	p.Height = 10
	p.Width = 70
	if _, err := tea.NewProgram(p, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run(); err != nil {
		fmt.Printf("error starting the ui: %v", err.Error())
	}
}

package main

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/impostorkeanu/eavesarp-ng/cmd/ui/panes"
	zone "github.com/lrstanley/bubblezone"
	"time"
)

type model struct {
	pane panes.LogsPane
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m.pane.Update(msg)
}

func (m model) View() string {
	return m.pane.View()
}

func (m model) Init() tea.Cmd {
	return m.pane.Init()
}

func main() {
	zone.NewGlobal()
	lCh, p := panes.NewLogsPane(1000, 200)

	go func() {
		for n := 0; n < 100; n++ {
			time.Sleep(1 * time.Second)
			lCh <- fmt.Sprintf("event %d", n)
		}
		lCh <- "done!"
	}()

	p.Style = lipgloss.NewStyle().Border(lipgloss.NormalBorder(), true, true, true, true)
	p.Height(10)
	p.Width(70)
	if _, err := tea.NewProgram(model{p}, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run(); err != nil {
		fmt.Printf("error starting the ui: %v", err.Error())
	}
}

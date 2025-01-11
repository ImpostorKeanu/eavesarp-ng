package main

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	zone "github.com/lrstanley/bubblezone"
	"strings"
)

type (
	button struct {
		text    string
		counter int
	}
	buttonRow struct {
		buttons []button
	}
)

var (
	buttonStyle = lipgloss.NewStyle().
		Background(lipgloss.Color("240")).
		Bold(true)
)

func (bR buttonRow) Init() tea.Cmd {
	return nil
}

func (bR buttonRow) View() string {
	var s []string
	//var s string
	for _, b := range bR.buttons {
		s = append(s, b.View())
		//s += lipgloss.NewStyle().Render(b.View())
	}
	//return zone.Scan(lipgloss.JoinHorizontal(lipgloss.Left, s...))
	return zone.Scan(strings.Join(s, " "))
}

func (bR buttonRow) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	for i, b := range bR.buttons {
		buff, _ := b.Update(msg)
		bR.buttons[i] = buff.(button)
	}
	return bR, nil
}

func (b button) Init() tea.Cmd {
	return nil
}

func (b button) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.MouseMsg:
		if zone.Get(b.text).InBounds(msg) && msg.Button == tea.MouseButtonLeft && msg.Action == tea.MouseActionPress {
			b.counter++
		}
	}
	return b, nil
}

func (b button) View() string {
	return zone.Mark(b.text, fmt.Sprintf("%s%d", b.text, b.counter))
}

func main() {
	zone.NewGlobal()
	bR := buttonRow{
		[]button{{text: "A"}, {text: "B"}, {text: "C"}},
		//[]button{{text: "A"}},
	}
	if _, err := tea.NewProgram(bR, tea.WithAltScreen(), tea.WithMouseCellMotion()).Run(); err != nil {
		panic(err)
	}
}

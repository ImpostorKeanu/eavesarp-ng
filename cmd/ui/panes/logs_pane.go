package panes

import (
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"slices"
	"strings"
)

type (
	LogsPane struct {
		Style          lipgloss.Style
		vp             viewport.Model
		events         []string
		maxEventLength int
		maxEventCount  int
		ch             chan string
	}
	LogEvent string
)

func NewLogsPane(maxEventLength, maxEventCount int) (chan string, LogsPane) {
	ch := make(chan string)
	return ch, LogsPane{
		Style:          lipgloss.Style{},
		vp:             viewport.New(0, 0),
		events:         make([]string, 0),
		maxEventLength: maxEventLength,
		maxEventCount:  maxEventCount,
		ch:             ch,
	}
}

func (l LogsPane) Init() tea.Cmd {
	return func() tea.Msg {
		return EmitEvent(l.ch)
	}
}

func (l LogsPane) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		l.vp, _ = l.vp.Update(msg)
	case LogEvent:
		s := string(msg)

		// Trim length of the log event
		if len(s) > l.maxEventLength {
			s = s[:l.maxEventLength-1]
		}

		// Trim 10% of logs when the maximum has been met to
		// make room for new events
		if len(l.events) >= l.maxEventCount {
			lN := len(l.events)
			l.events = slices.Delete(l.events, lN-(lN/10), lN-1)
		}

		// Capture the event and write to the viewport
		l.events = append(l.events, s)
		l.vp.SetContent(strings.Join(l.events, "\n"))

		// Return the model and start a new process to catch the
		// next event, which is handled by the event loop managed
		// by charmbracelet.
		return l, func() tea.Msg {
			return LogEvent(<-l.ch)
		}
	}

	return l, nil
}

func (l LogsPane) View() string {
	if l.vp.YOffset == 0 && l.vp.Height > 0 {
		// Scroll to the bottom of the logs viewport
		l.vp.GotoBottom()
	}
	l.vp.Style = l.Style
	return l.vp.View()
}

func EmitEvent(c chan string) tea.Msg {
	return LogEvent(<-c)
}

func (l *LogsPane) Height(height int) {
	l.vp.Height = height
}

func (l *LogsPane) Width(width int) {
	l.vp.Width = width
}

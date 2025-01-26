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
		headingZoneId  string
		events         []string
		maxEventLength int
		maxEventCount  int
		ch             chan string
	}
	LogEvent string
)

func NewLogsPane(maxEventLength, maxEventCount int, headingZoneId string) (chan string, LogsPane) {
	ch := make(chan string)
	return ch, LogsPane{
		Style:          lipgloss.Style{},
		vp:             viewport.New(0, 0),
		headingZoneId:  headingZoneId,
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
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		l.vp, cmd = l.vp.Update(msg)
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

		// Check if the viewport is at the bottom before setting
		// additional lines
		wasAtBottom := l.vp.AtBottom()

		// Capture the event and write to the viewport
		l.events = append(l.events, s)
		l.vp.SetContent(strings.Join(l.events, "\n"))

		if wasAtBottom && (l.vp.TotalLineCount() >= l.vp.Height) {
			// Stick to the bottom unless we've scrolled up
			l.vp.GotoBottom()
		}

		// Return the model and start a new process to catch the
		// next event, which is handled by the event loop managed
		// by charmbracelet.
		return l, func() tea.Msg {
			return LogEvent(<-l.ch)
		}
	}

	return l, cmd
}

func (l LogsPane) View() string {
	//if l.vp.YOffset == 0 && l.vp.SetHeight > 0 {
	//	// Scroll to the bottom of the logs viewport
	//	l.vp.GotoBottom()
	//}
	l.vp.Style = l.Style
	return l.vp.View()
}

func EmitEvent(c chan string) tea.Msg {
	return LogEvent(<-c)
}

func (l *LogsPane) SetHeight(h int) {
	l.vp.Height = h
}

func (l *LogsPane) Height() int {
	return l.vp.Height
}

func (l *LogsPane) SetWidth(w int) {
	l.vp.Width = w + 1
}

func (l *LogsPane) AtBottom() bool {
	return l.vp.AtBottom()
}

func (l *LogsPane) GoToBottom() {
	l.vp.GotoBottom()
}

func (l *LogsPane) LineDown(n int) {
	l.vp.LineDown(n)
}

func (l *LogsPane) LineUp(n int) {
	l.vp.LineUp(n)
}

func (l *LogsPane) YOffset() int {
	return l.vp.YOffset
}

func (l *LogsPane) TotalLineCount() int {
	return l.vp.TotalLineCount()
}

func (l *LogsPane) VisibleLineCount() int {
	return l.vp.VisibleLineCount()
}

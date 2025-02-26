package timer

import (
	tea "github.com/charmbracelet/bubbletea"
	"time"
)

type (
	StartStopMsg struct {
		Id      string
		running bool
	}
	TickMsg struct {
		Id      string
		Timeout bool
		tag     int
	}
	TimeoutMsg struct {
		Id  string
		tag int
	}
	Model struct {
		Timeout  time.Duration
		Interval time.Duration
		start    time.Time
		end      time.Time
		id       string
		running  bool
		tag      int
	}
)

func New(id string, timeout time.Duration) Model {
	return Model{
		Timeout:  timeout,
		Interval: time.Second,
		id:       id,
		running:  false,
	}
}

func (m Model) ID() string {
	return m.id
}

func (m Model) Running() bool {
	if m.Timedout() || !m.running {
		return false
	}
	return true
}

func (m Model) Timedout() bool {
	return time.Now().Equal(m.end) || time.Now().After(m.end)
}

func (m Model) View() string {
	return m.end.Sub(time.Now()).Round(time.Second).String()
}

func (m *Model) Start() tea.Cmd {
	return m.startStop(true)
}

func (m *Model) Stop() tea.Cmd {
	return m.startStop(false)
}

func (m *Model) Toggle() tea.Cmd {
	return m.startStop(!m.Running())
}

func (m Model) tick() tea.Cmd {
	return tea.Tick(m.Interval, func(_ time.Time) tea.Msg {
		return TickMsg{Id: m.id, Timeout: m.Timedout(), tag: m.tag}
	})
}

// Update handles the timer tick.
func (m Model) Update(msg tea.Msg) (_ Model, cmd tea.Cmd) {
	switch msg := msg.(type) {
	case StartStopMsg:
		if msg.Id != m.id {
			break
		}
		m.running = msg.running
		m.tag++
		if m.running && m.start.IsZero() {
			m.start = time.Now()
			m.end = m.start.Add(m.Timeout).Round(time.Second)
		} else if !m.Running() {
			break
		}
		cmd = m.tick()

	case TickMsg:
		if !m.Running() || msg.Id != m.id || msg.tag != m.tag {
			break
		}
		m.tag++
		cmd = tea.Batch(m.tick(), m.timedout())
	}

	return m, cmd
}

func (m Model) timedout() tea.Cmd {
	if !m.Timedout() {
		return nil
	}
	return func() tea.Msg {
		return TimeoutMsg{Id: m.id, tag: m.tag}
	}
}

func (m Model) startStop(v bool) tea.Cmd {
	return func() tea.Msg {
		return StartStopMsg{Id: m.id, running: v}
	}
}

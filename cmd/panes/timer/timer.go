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
	}
	TimeoutMsg struct {
		Id string
	}
	Model struct {
		Timeout  time.Duration
		Interval time.Duration
		last     time.Time
		id       string
		running  bool
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
	return m.Timeout <= 0
}

func (m Model) View() string {
	return m.Timeout.Round(time.Second).String()
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
		return TickMsg{Id: m.id, Timeout: m.Timedout()}
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
		if !m.Running() {
			break
		} else if !m.last.IsZero() {
			m.Timeout -= time.Since(m.last)
		}
		cmd = m.tick()

	case TickMsg:
		if !m.Running() || msg.Id != m.id {
			break
		}
		m.last = time.Now()
		m.Timeout -= m.Interval
		cmd = tea.Batch(m.tick(), m.timedout())
	}

	return m, cmd
}

func (m Model) timedout() tea.Cmd {
	if !m.Timedout() {
		return nil
	}
	return func() tea.Msg {
		return TimeoutMsg{Id: m.id}
	}
}

func (m Model) startStop(v bool) tea.Cmd {
	return func() tea.Msg {
		return StartStopMsg{Id: m.id, running: v}
	}
}

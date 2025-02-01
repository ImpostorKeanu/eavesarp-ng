package stopwatch

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"time"
)

type (
	// Model is used to track elapsed time for poisoning attacks
	// without a time limit. It's adapted from the bubbles module to
	// suit our need of tracking multiple attacks without excess
	// messages being sent to the tea control loop.
	//
	// It works by capturing a timestamp of each received tick. When
	// a Model is stopped and started again, the running duration
	// is derived by summing it with the time passed since receipt of
	// the last stop message.
	Model struct {
		id       string
		d        time.Duration // How long the Model has been ticking
		running  bool          // is the Model running?
		interval time.Duration // interval to tick
		// Time of last tick.
		//
		// When restarted, this value is used to determine how long
		// the Model has actually been running.
		last time.Time
	}
	StartStopMsg struct {
		Id      string
		running bool
	}
	TickMsg struct {
		Id string
	}
)

func NewStopwatch(srcIp, targetIp string, last time.Time, interval time.Duration) Model {
	return Model{
		id:       fmt.Sprintf("%s:%s", srcIp, targetIp),
		running:  false,
		last:     last,
		interval: interval,
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Start() tea.Cmd {
	return func() tea.Msg {
		return StartStopMsg{Id: m.id, running: true}
	}
}

func (m *Model) Stop() tea.Cmd {
	return func() tea.Msg {
		return StartStopMsg{Id: m.id, running: false}
	}
}

func (m Model) Running() bool {
	return m.running
}

func (m Model) View() string {
	return m.d.String()
}

func (m Model) Update(msg tea.Msg) (_ Model, cmd tea.Cmd) {
	switch msg := msg.(type) {
	case StartStopMsg:
		if m.id != msg.Id {
			break
		}
		m.running = msg.running
		if msg.running {
			if !m.last.IsZero() {
				m.d += time.Since(m.last).Round(time.Second)
			}
			cmd = tick(m.id, m.interval)
		}
	case TickMsg:
		if !m.running || m.id != msg.Id {
			break
		}
		m.last = time.Now()
		m.d += m.interval
		cmd = tick(m.id, m.interval)
	}
	return m, cmd
}

func tick(id string, d time.Duration) tea.Cmd {
	return tea.Tick(d, func(_ time.Time) tea.Msg {
		return TickMsg{Id: id}
	})
}

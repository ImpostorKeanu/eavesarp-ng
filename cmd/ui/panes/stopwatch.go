package panes

import (
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"time"
)

type (
	Stopwatch struct {
		id       string
		d        time.Duration // How long the Stopwatch has been ticking
		running  bool          // is the Stopwatch running?
		last     time.Time     // last time ticked time
		Interval time.Duration // Interval to tick
	}
	StartStopMsg struct {
		Id      string
		running bool
	}
	TickMsg struct {
		Id string
	}
)

func NewStopwatch(srcIp, targetIp string, last time.Time, interval time.Duration) Stopwatch {
	return Stopwatch{
		id:       fmt.Sprintf("%s:%s", srcIp, targetIp),
		running:  false,
		last:     last,
		Interval: interval,
	}
}

func (m Stopwatch) Init() tea.Cmd {
	return nil
}

func (m Stopwatch) Start() tea.Cmd {
	return func() tea.Msg {
		return StartStopMsg{Id: m.id, running: true}
	}
}

func (m *Stopwatch) Stop() tea.Cmd {
	return func() tea.Msg {
		return StartStopMsg{Id: m.id, running: false}
	}
}

func (m Stopwatch) Running() bool {
	return m.running
}

func (m Stopwatch) View() string {
	return m.d.String()
}

func (m Stopwatch) Update(msg tea.Msg) (Stopwatch, tea.Cmd) {
	var cmd tea.Cmd
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
			cmd = tick(m.id, m.Interval)
		}
	case TickMsg:
		if !m.running || m.id != msg.Id {
			break
		}
		m.last = time.Now()
		m.d += m.Interval
		cmd = tick(m.id, m.Interval)
	}
	return m, cmd
}

func tick(id string, d time.Duration) tea.Cmd {
	return tea.Tick(d, func(_ time.Time) tea.Msg {
		return TickMsg{Id: id}
	})
}

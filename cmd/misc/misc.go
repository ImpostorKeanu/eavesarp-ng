package misc

import (
	"fmt"
	"github.com/charmbracelet/lipgloss"
	"slices"
	"sync"
)

const (
	MaxLogCount                   = 1000 // Maximum number of logs to display
	MaxLogLength                  = 2000 // Maximum length of a log event
	ConvosPaneId    PaneHeadingId = "convosTable"
	CurConvoPaneId  PaneHeadingId = "convoTable"
	LogPaneId       PaneHeadingId = "logsViewPort"
	PoisonCfgPaneId PaneHeadingId = "poisonCfgPane"
)

var (
	SelectedPaneBorderColor    = lipgloss.AdaptiveColor{Light: "232", Dark: "248"}
	DeselectedPaneBorderColor  = lipgloss.AdaptiveColor{Light: "252", Dark: "240"}
	SelectedRowForegroundColor = lipgloss.AdaptiveColor{Light: "232", Dark: "255"}
	BtnColor                   = lipgloss.AdaptiveColor{Light: "236", Dark: "241"}
	BlurredColor               = lipgloss.AdaptiveColor{Light: "236", Dark: "240"}
	FailedValidationColor      = lipgloss.AdaptiveColor{Light: "52", Dark: "160"}
	SuccessValidationColor     = lipgloss.AdaptiveColor{Light: "34", Dark: "76"}
	BtnTextColor               = lipgloss.AdaptiveColor{Light: "253", Dark: "255"}
)

// EventWriter is used to write formatted logs to a channel.
type EventWriter struct {
	c chan string
}

func NewEventWriter(c chan string) *EventWriter {
	return &EventWriter{c: c}
}

func (e EventWriter) WriteString(s string) (n int, err error) {
	l := len(s)
	if len(s) > MaxLogLength {
		s = s[:MaxLogLength-l]
		l = len(s)
	}
	if l > 0 {
		e.c <- s
	}
	return l, nil
}

func (e EventWriter) WriteStringf(f string, args ...any) (n int, err error) {
	return e.WriteString(fmt.Sprintf(f, args...))
}

// ActiveAttacks is a concurrency safe container to track ongoing poisoning
// attacks.
type ActiveAttacks struct {
	m       sync.RWMutex
	attacks []string
}

func (a *ActiveAttacks) Exists(convoKey string) bool {
	a.m.RLock()
	defer a.m.RUnlock()
	return slices.Contains(a.attacks, convoKey)
}

func (a *ActiveAttacks) Remove(convoKey string) {
	a.m.Lock()
	defer a.m.Unlock()
	l := len(a.attacks)
	if l == 0 {
		return
	}
	if ind := slices.Index(a.attacks, convoKey); ind != -1 {
		if l == 1 {
			a.attacks = make([]string, 0)
			return
		}

		// copy first half up to element to be omitted
		head := a.attacks[:ind]

		// get remaining elements
		var tail []string
		if l-1 >= ind+1 {
			tail = a.attacks[ind+1:]
		}

		// concatenate the slices
		a.attacks = slices.Concat(head, tail)
	}
}

func (a *ActiveAttacks) Add(convoKey string) (err error) {
	a.m.Lock()
	defer a.m.Unlock()
	if !slices.Contains(a.attacks, convoKey) {
		a.attacks = append(a.attacks, convoKey)
	} else {
		err = fmt.Errorf("already exists", convoKey)
	}
	return
}

// PaneHeadingId represents a bubble zone mark ID used to
// identify a UI pane.
type PaneHeadingId string

func (p PaneHeadingId) String() string {
	return string(p)
}

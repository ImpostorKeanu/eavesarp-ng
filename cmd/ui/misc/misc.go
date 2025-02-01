package misc

import (
	"fmt"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
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

func (a *ActiveAttacks) Exists(senderIp, targetIp string) bool {
	a.m.RLock()
	defer a.m.RUnlock()
	return slices.Contains(a.attacks, eavesarp_ng.FmtConvoKey(senderIp, targetIp))
}

func (a *ActiveAttacks) Remove(senderIp, targetIp string) {
	a.m.Lock()
	defer a.m.Unlock()
	l := len(a.attacks)
	if l == 0 {
		return
	}
	s := eavesarp_ng.FmtConvoKey(senderIp, targetIp)
	if ind := slices.Index(a.attacks, s); ind != -1 {
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

func (a *ActiveAttacks) Add(senderIp, targetIp string) (err error) {
	a.m.Lock()
	defer a.m.Unlock()
	s := eavesarp_ng.FmtConvoKey(senderIp, targetIp)
	if !slices.Contains(a.attacks, s) {
		a.attacks = append(a.attacks, s)
	} else {
		err = fmt.Errorf("%s already exists", s)
	}
	return
}

// PaneHeadingId represents a bubble zone mark ID used to
// identify a UI pane.
type PaneHeadingId string

func (p PaneHeadingId) String() string {
	return string(p)
}

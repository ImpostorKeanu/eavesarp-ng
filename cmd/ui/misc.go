package main

import (
	"errors"
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/impostorkeanu/eavesarp-ng/cmd/ui/panes"
	zone "github.com/lrstanley/bubblezone"
	"slices"
	"sync"
)

var (
	PoisoningPanelAlreadyExistsError = errors.New("poisoning panel already exists")
	PoisoningPanelDoesntExistError   = errors.New("poisoning panel doesn't exist")
)

type (
	eventWriter struct {
		wC chan string
	}
	ActiveAttacks struct {
		attacks []string
		mu      sync.RWMutex
	}
	PoisoningPanels struct {
		panels map[string]*panes.PoisonPane
		mu     sync.RWMutex
	}
)

func (e eventWriter) WriteString(s string) (n int, err error) {
	l := len(s)
	if len(s) > maxLogLength {
		s = s[:maxLogLength-l]
		l = len(s)
	}
	if l > 0 {
		e.wC <- s
	}
	return l, nil
}

func (e eventWriter) WriteStringf(f string, args ...any) (n int, err error) {
	return e.WriteString(fmt.Sprintf(f, args...))
}

func (a *ActiveAttacks) Exists(senderIp, targetIp string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return slices.Contains(a.attacks, FmtConvoKey(senderIp, targetIp))
}

func (a *ActiveAttacks) Remove(senderIp, targetIp string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// return if zero active attacks are occurring
	l := len(a.attacks)
	if l == 0 {
		return
	}

	s := FmtConvoKey(senderIp, targetIp)
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
	a.mu.Lock()
	defer a.mu.Unlock()
	s := FmtConvoKey(senderIp, targetIp)
	if !slices.Contains(a.attacks, s) {
		a.attacks = append(a.attacks, s)
	} else {
		err = fmt.Errorf("%s already exists", s)
	}
	return
}

// FmtConvoKey returns the IPs formatted for common lookups.
func FmtConvoKey(senderIp, targetIp string) string {
	return fmt.Sprintf("%s:%s", senderIp, targetIp)
}

func (p *PoisoningPanels) Exists(senderIp, targetIp string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.exists(senderIp, targetIp)
}

func (p *PoisoningPanels) Remove(senderIp, targetIp string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.panels, FmtConvoKey(senderIp, targetIp))
}

func (p *PoisoningPanels) Add(senderIp, targetIp string, panel *panes.PoisonPane) (err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.add(senderIp, targetIp, panel)
}

func (p *PoisoningPanels) Update(senderIp, targetIp string, msg tea.Msg) (cmd tea.Cmd, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.exists(senderIp, targetIp) {
		var buff tea.Msg
		buff, cmd = p.panels[FmtConvoKey(senderIp, targetIp)].Update(msg)
		*p.panels[FmtConvoKey(senderIp, targetIp)] = buff.(panes.PoisonPane)
	} else {
		err = PoisoningPanelDoesntExistError
	}
	return
}

func (p *PoisoningPanels) GetOrCreate(senderIp, targetIp string) (panel *panes.PoisonPane) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if panel = p.panels[FmtConvoKey(senderIp, targetIp)]; panel == nil {
		buff := panes.NewPoison(zone.DefaultManager)
		panel = &buff
		p.panels[FmtConvoKey(senderIp, targetIp)] = panel
	}
	return
}

func (p *PoisoningPanels) Get(senderIp, targetIp string) *panes.PoisonPane {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.panels[FmtConvoKey(senderIp, targetIp)]
}

func (p *PoisoningPanels) exists(senderIp, targetIp string) bool {
	return p.panels[FmtConvoKey(senderIp, targetIp)] != nil
}

func (p *PoisoningPanels) add(senderIp, targetIp string, panel *panes.PoisonPane) (err error) {
	if p.exists(senderIp, targetIp) {
		return PoisoningPanelAlreadyExistsError
	}
	p.panels[FmtConvoKey(senderIp, targetIp)] = panel
	return
}

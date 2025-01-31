package main

import (
	"errors"
	tea "github.com/charmbracelet/bubbletea"
	eavesarp_ng "github.com/impostorkeanu/eavesarp-ng"
	"github.com/impostorkeanu/eavesarp-ng/cmd/ui/panes"
	zone "github.com/lrstanley/bubblezone"
	"sync"
)

var (
	ppMu                             sync.RWMutex
	poisonPanes                      = make(PoisoningPanes)
	PoisoningPanelAlreadyExistsError = errors.New("poisoning panel already exists")
	PoisoningPanelDoesntExistError   = errors.New("poisoning panel doesn't exist")

	poisonPaneLm = eavesarp_ng.NewConvoLockMap(make(map[string]*panes.PoisonPane))
)

type PoisoningPanes map[string]*panes.PoisonPane

func (p PoisoningPanes) Exists(senderIp, targetIp string) bool {
	return p.exists(senderIp, targetIp)
}

func (p PoisoningPanes) Remove(senderIp, targetIp string) {
	delete(p, FmtConvoKey(senderIp, targetIp))
}

func (p PoisoningPanes) Add(senderIp, targetIp string, panel *panes.PoisonPane) (err error) {
	return p.add(senderIp, targetIp, panel)
}

func (p PoisoningPanes) Update(senderIp, targetIp string, msg tea.Msg) (cmd tea.Cmd, err error) {
	ppMu.Lock()
	if p.exists(senderIp, targetIp) {
		var buff tea.Msg
		buff, cmd = p[FmtConvoKey(senderIp, targetIp)].Update(msg)
		b2 := buff.(panes.PoisonPane)
		p[FmtConvoKey(senderIp, targetIp)] = &b2
	} else {
		err = PoisoningPanelDoesntExistError
	}
	ppMu.Unlock()
	return
}

func (p PoisoningPanes) GetOrCreate(senderIp, targetIp string) (panel *panes.PoisonPane) {
	ppMu.Lock()
	if panel = p[FmtConvoKey(senderIp, targetIp)]; panel == nil {
		buff := panes.NewPoison(zone.DefaultManager, senderIp, targetIp)
		panel = &buff
		p[FmtConvoKey(senderIp, targetIp)] = panel
	}
	ppMu.Unlock()
	return
}

func (p PoisoningPanes) Get(senderIp, targetIp string) (n *panes.PoisonPane) {
	ppMu.RLock()
	n = p[FmtConvoKey(senderIp, targetIp)]
	ppMu.RUnlock()
	return
}

func (p PoisoningPanes) exists(senderIp, targetIp string) (e bool) {
	ppMu.RLock()
	e = p[FmtConvoKey(senderIp, targetIp)] != nil
	ppMu.RUnlock()
	return
}

func (p PoisoningPanes) add(senderIp, targetIp string, panel *panes.PoisonPane) (err error) {
	if p.exists(senderIp, targetIp) {
		return PoisoningPanelAlreadyExistsError
	}
	ppMu.Lock()
	p[FmtConvoKey(senderIp, targetIp)] = panel
	ppMu.Unlock()
	return
}

package main

import (
	"fmt"
	"slices"
	"sync"
)

type (
	eventWriter struct {
		wC chan string
	}
	ActiveAttacks struct {
		attacks []string
		mu      sync.RWMutex
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
	s := FmtConvoKey(senderIp, targetIp)
	if ind := slices.Index(a.attacks, s); ind != -1 {
		var n []string
		if len(a.attacks) == 1 {
			a.attacks = make([]string, 0)
			return
		} else {
			n = make([]string, len(a.attacks)-1)
		}
		copy(n, a.attacks[:ind])
		if len(a.attacks)-1 >= ind+1 {
			copy(n, a.attacks[ind+1:])
		}
		a.attacks = n
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

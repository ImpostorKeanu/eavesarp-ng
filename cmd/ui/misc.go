package main

import (
	"fmt"
	"slices"
)

type (
	eventWriter struct {
		wC chan string
	}
	ActiveAttacks struct {
		attacks []string
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
	return slices.Contains(a.attacks, FmtConvoKey(senderIp, targetIp))
}

func (a *ActiveAttacks) Remove(senderIp, targetIp string) {

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

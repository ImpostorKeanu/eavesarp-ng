package main

import (
	"fmt"
)

type eventWriter struct {
	wC chan string
}

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

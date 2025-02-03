package eavesarp_ng

import (
	"fmt"
	"io"
	"sync"
)

// EventWriters are used to send eavesarp events to applications.
//
// Any type that implements io.StringWriter can be a writer.
type EventWriters struct {
	writers []io.StringWriter
	mu      sync.Mutex
}

func NewEventWriters(writers ...io.StringWriter) *EventWriters {
	return &EventWriters{writers: writers}
}

func (e *EventWriters) Write(s string) (errs map[io.StringWriter]error) {
	e.write(s, &errs)
	return
}

func (e *EventWriters) Writef(format string, a ...any) (errs map[io.StringWriter]error) {
	e.write(fmt.Sprintf(format, a...), &errs)
	return errs
}

func (e *EventWriters) write(s string, errs *map[io.StringWriter]error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, w := range e.writers {
		_, err := w.WriteString(s)
		if err != nil {
			if *errs == nil {
				*errs = make(map[io.StringWriter]error)
			}
			(*errs)[w] = err
		}
	}
}

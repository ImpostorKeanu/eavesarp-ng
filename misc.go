package eavesarp_ng

import (
	"sync"
)

type (
	// FailCounter is used to track the number of failures that
	// have occurred. It allows application to determine when
	// to stop performing some type of action that may be detrimental
	// to the network, e.g., making repeated DNS queries when the
	// server is failing.
	FailCounter struct {
		max   int
		count int
		mu    sync.RWMutex
	}
)

// Inc increments the fail counter.
func (f *FailCounter) Inc() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.count < f.max {
		f.count++
	}
}

// Exceeded determines if the failure threshold has been
// exceeded.
func (f *FailCounter) Exceeded() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.count >= f.max
}

// Count returns the current count of failures.
func (f *FailCounter) Count() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.count
}

// NewFailCounter initializes a new FailCounter.
func NewFailCounter(max int) (fC *FailCounter) {
	return &FailCounter{max: max, mu: sync.RWMutex{}}
}

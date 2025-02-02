package eavesarp_ng

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"
)

var (
	rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
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

	// Sleeper is used to sleep a thread for a period of time.
	// This type is used to throttle ARP and DNS name resolution
	// requests/responses.
	//
	// Jitter Logic:
	//
	// 1. Jitter is derived by calculating a random value between
	//    zero and jitterMax
	// 2. The jitter is either added -OR- subtracted from window.
	Sleeper struct {
		// winMin is the minimum end of the sleep window.
		winMin int
		// winMax is the maximum end of the sleep window.
		winMax int
		// window is the pure number of seconds to sleep without
		// considering jitterMax.
		//
		// Calculated as (winMax - winMin)
		window float64
		// Percentage variability in sleep duration.
		jitterMax int
	}

	ConvoLockMap[T any] struct {
		mu sync.RWMutex
		m  map[string]*T
	}
)

func NewConvoLockMap[T any](m map[string]*T) *ConvoLockMap[T] {
	return &ConvoLockMap[T]{m: m}
}

func (l *ConvoLockMap[T]) Get(key string) *T {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.m[key]
}

func (l *ConvoLockMap[T]) Set(key string, value *T) {
	l.mu.Lock()
	l.m[key] = value
	l.mu.Unlock()
}

func (l *ConvoLockMap[T]) Delete(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}

func (l *ConvoLockMap[T]) Update(key string, f func(*T)) {
	l.mu.Lock()
	f(l.m[key])
	l.mu.Unlock()
}

func (l *ConvoLockMap[T]) CGet(sIp, tIp string) *T {
	return l.Get(FmtConvoKey(sIp, tIp))
}

func (l *ConvoLockMap[T]) CSet(sIp, tIp string, v *T) {
	l.Set(FmtConvoKey(sIp, tIp), v)
}

func (l *ConvoLockMap[T]) CDelete(sIp, tIp string) {
	l.Delete(FmtConvoKey(sIp, tIp))
}

func (l *ConvoLockMap[T]) CUpdate(sIp, tIp string, f func(*T)) {
	l.Update(FmtConvoKey(sIp, tIp), f)
}

func (s Sleeper) Sleep() {
	jitter := s.window * (rnd.Float64() * (float64(s.jitterMax) / 100))
	var t float64
	if rnd.Intn(1) == 1 {
		t = s.window + jitter
	} else {
		t = s.window - jitter
	}
	v := time.Second * time.Duration(int(math.Round(t)))
	time.Sleep(v)
}

func NewSleeper(minWin, maxWin, jitterMaxPercentage int) Sleeper {
	return Sleeper{minWin, maxWin, float64(maxWin - minWin), jitterMaxPercentage}
}

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

// GreaterLength will split a string on newlines and set i
// to the longest length line so long as it is greater than
// the supplied value.
func GreaterLength(s string, i *int) {
	for _, x := range strings.Split(s, "\n") {
		if len(x) > *i {
			*i = len(x)
		}
	}
}

// EmptyOrDefault sets the value of s to d if it's currently
// empty.
func EmptyOrDefault(s *string, d string) {
	if *s == "" {
		*s = d
	}
}

func Longest(s []string) (e string, i int) {
	for _, ele := range s {
		if len(ele) > i {
			i = len(ele)
			e = ele
		}
	}
	return
}

// FmtConvoKey returns the IPs formatted for common lookups.
func FmtConvoKey(senderIp, targetIp string) string {
	return fmt.Sprintf("%s:%s", senderIp, targetIp)
}

func SplitConvoKey(v string) (senderIp string, targetIp string, err error) {
	s := strings.Split(v, ":")
	if len(v) >= 2 {
		senderIp, targetIp = s[0], s[1]
	} else {
		err = errors.New("poorly formatted value supplied")
	}
	return
}

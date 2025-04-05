package eavesarp_ng

import (
	"errors"
	"fmt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"math"
	"math/rand"
	"strings"
	"sync"
	"time"
)

const (
	ConversationKeyDelimiter = ":"
	DnsKeyDelimiter          = ":"
)

var (
	rnd = rand.New(rand.NewSource(time.Now().UnixNano()))
)

type (
	// FailCounter is used to track the number of failures that
	// have occurred. It allows the application to determine when
	// to stop performing some type of action that may be detrimental
	// to the network, e.g., making repeated DNS queries when the
	// server is failing.
	FailCounter struct {
		max   int
		count int
		mu    sync.RWMutex
	}

	// Sleeper is used to sleep a routine for a period of time.
	// Jitter is applied at each call, adding some randomization
	// to the sleep time. This type is used to throttle ARP and
	// DNS name resolution requests/responses.
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

	// LockMap is effectively a mapping of string to any values that
	// uses mutexes to ensure controlled access.
	LockMap[T any] struct {
		mu sync.RWMutex
		m  map[string]*T
	}

	// ConvoLockMap is LockMap with additional methods that act on the
	// md5, which is typically in the form of `{SenderIP}:{TargetIP}`.
	// Methods prefixed with `C` are effectively aliases to standard
	// LockMap methods, except they receive individual arguments for
	// the sender and target IP addresses.
	ConvoLockMap[T any] struct {
		LockMap[T]
	}

	CtxKey string

	// refCounter is used to track the number of items referencing
	// a type instance.
	refCounter struct {
		mu sync.RWMutex
		c  int
	}
)

// inc Increments c.
func (a *refCounter) inc() {
	a.mu.Lock()
	a.c++
	a.mu.Unlock()
}

// dec decrements c.
func (a *refCounter) dec() (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.c == 0 {
		return 0, errors.New("ref count is zero")
	}
	a.c--
	return a.c, nil
}

// count returns c.
func (a *refCounter) count() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.c
}

func NewLockMap[T any](m map[string]*T) *LockMap[T] {
	return &LockMap[T]{m: m}
}

func NewConvoLockMap[T any](m map[string]*T) *ConvoLockMap[T] {
	return &ConvoLockMap[T]{LockMap[T]{m: m}}
}

func (l *LockMap[T]) Get(key string) *T {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.m[key]
}

func (l *LockMap[T]) Extract(key string) (v *T) {
	l.mu.Lock()
	v = l.m[key]
	delete(l.m, key)
	l.mu.Unlock()
	return
}

func (l *LockMap[T]) Set(key string, value *T) {
	l.mu.Lock()
	l.m[key] = value
	l.mu.Unlock()
}

func (l *LockMap[T]) Delete(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}

func (l *LockMap[T]) Update(key string, f func(*T)) {
	l.mu.Lock()
	f(l.m[key])
	l.mu.Unlock()
}

func (l *ConvoLockMap[T]) CGet(sIp, tIp string) *T {
	return l.Get(FmtConvoKey(sIp, tIp))
}

func (l *ConvoLockMap[T]) CExtract(sIp, tIp string) *T {
	return l.Extract(FmtConvoKey(sIp, tIp))
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

// Exceeded determines if the FailureF threshold has been
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

// FmtConvoKey returns the IPs formatted for common lookups.
func FmtConvoKey(senderIp, targetIp string) string {
	return fmt.Sprintf("%s%s%s", senderIp, ConversationKeyDelimiter, targetIp)
}

// SplitConvoKey breaks apart the conversation md5 and returns the
// sender and target IP values.
func SplitConvoKey(v string) (senderIp string, targetIp string, err error) {
	s := strings.Split(v, ConversationKeyDelimiter)
	if len(v) >= 2 {
		senderIp, targetIp = s[0], s[1]
	} else {
		err = errors.New("poorly formatted value supplied")
	}
	return
}

// FmtDnsKey returns a string value that's properly formatted
// for use various eavesarp_ng functions and methods.
func FmtDnsKey(target string, kind DnsRecordKind) string {
	return fmt.Sprintf("%s%s%s", target, DnsKeyDelimiter, kind)
}

// NewLogger instantiates a Zap logger for the eavesarp_ng module.
//
// level is one of:
//
// - debug
// - info
// - warn
// - error
// - dpanic
// - panic
// - fatal
//
// outputPaths and errOutputPaths is file paths or URLs to write logs
// to. Setting outputPaths to nil configures the logger to send non-error
// records to stdout, and setting errOutputPaths to nil configures the
// logger to send error records to stderr.
func NewLogger(level string, outputPaths, errOutputPaths []string) (*zap.Logger, error) {

	if outputPaths == nil {
		outputPaths = []string{"stdout"}
	}
	if errOutputPaths == nil {
		errOutputPaths = []string{"stderr"}
	}

	lvl, err := zap.ParseAtomicLevel(level)
	if err != nil {
		return nil, fmt.Errorf("error parsing log level: %v", err)
	}

	zapCfg := zap.Config{
		Level:             lvl,
		Development:       false,
		DisableCaller:     false,
		DisableStacktrace: false,
		Sampling:          nil,
		Encoding:          "json",
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:  "message",
			LevelKey:    "level",
			TimeKey:     "time",
			EncodeLevel: zapcore.LowercaseLevelEncoder,
			EncodeTime:  zapcore.ISO8601TimeEncoder,
		},
		OutputPaths:      outputPaths,
		ErrorOutputPaths: errOutputPaths,
	}

	return zapCfg.Build()
}

// optInt returns an integer weight assigned to known NewCfg options.
func optInt(v any) (i int, err error) {
	switch v.(type) {
	case DefaultDownstreamOpt:
		i = DefaultDownstreamOptWeight
	case DefaultTCPServerOpts:
		i = DefaultTCPServerOptWeight
	case DefaultProxyServerAddrOpt:
		i = DefaultProxyServerOptWeight
	default:
		err = errors.New("unknown opt type")
	}
	return
}

package underlay

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// bindLogEvery spaces the warnings of failed bindings.
const bindLogEvery = 10 * time.Second

var (
	logger      atomic.Pointer[slog.Logger]
	lastBindLog struct {
		sync.Mutex
		at time.Time
	}
)

// SetLogger sets where failures to keep the client's sockets on the
// physical path are reported; nil reports nothing.
func SetLogger(l *slog.Logger) { logger.Store(l) }

// ReportBindFailure warns, at most every 10 s, that a socket of what could
// not be kept on the physical path: it follows the mesh routes then.
func ReportBindFailure(what string, err error) {
	l := logger.Load()
	if l == nil || err == nil {
		return
	}
	lastBindLog.Lock()
	due := time.Since(lastBindLog.at) >= bindLogEvery
	if due {
		lastBindLog.at = time.Now()
	}
	lastBindLog.Unlock()
	if due {
		l.Warn("keeping a socket on the physical path failed", "socket", what, "error", err)
	}
}

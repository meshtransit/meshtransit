package underlay

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// reportEvery spaces the reports of one kind.
const reportEvery = 10 * time.Second

var (
	logger      atomic.Pointer[slog.Logger]
	lastReports struct {
		sync.Mutex
		at map[string]time.Time
	}
)

// SetLogger sets where the client's own sockets report what they do off the
// mesh routes; nil reports nothing.
func SetLogger(l *slog.Logger) { logger.Store(l) }

// due reports whether a report of kind may be logged now, at most every
// reportEvery.
func due(kind string) bool {
	now := time.Now()
	lastReports.Lock()
	defer lastReports.Unlock()
	if lastReports.at == nil {
		lastReports.at = map[string]time.Time{}
	}
	if now.Sub(lastReports.at[kind]) < reportEvery {
		return false
	}
	lastReports.at[kind] = now
	return true
}

// ReportBindFailure warns, at most every 10 s, that a socket of what could
// not be kept on the physical path: it follows the mesh routes then.
func ReportBindFailure(what string, err error) {
	ReportFailure("keeping a socket on the physical path failed", what, err)
}

// ReportFailure warns, at most every 10 s for each message and subject,
// that subject failed with err.
func ReportFailure(message, subject string, err error) {
	l := logger.Load()
	if l == nil || err == nil || !due(message+"\x00"+subject) {
		return
	}
	l.Warn(message, "subject", subject, "error", err)
}

// reportExitBound notes that the client's own sockets now keep off the mesh
// routes, or follow the host's routes again.
func reportExitBound(sources uint32) {
	l := logger.Load()
	if l == nil {
		return
	}
	if sources == 0 {
		l.Info("own sockets follow the host's routes again")
		return
	}
	l.Info("own sockets keep off the mesh routes", "requested", sources&uint32(ExitRequested) != 0,
		"held", sources&uint32(ExitHeld) != 0, "chosen", sources&uint32(ExitChosen) != 0)
}

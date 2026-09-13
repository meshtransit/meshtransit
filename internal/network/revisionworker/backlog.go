package revisionworker

import (
	"errors"
	"time"
)

var (
	// ErrInvalidBacklog indicates an impossible outbox backlog observation.
	ErrInvalidBacklog = errors.New("invalid network revision backlog")
)

// Backlog is a point-in-time observation of Network-revision events that are
// ready to be claimed. It deliberately excludes retries whose delay has not
// elapsed and claims whose lease is still live.
type Backlog struct {
	events    int64
	oldestAge time.Duration
}

// NewBacklog validates one ready-work observation.
func NewBacklog(events int64, oldestAge time.Duration) (Backlog, error) {
	if events < 0 || oldestAge < 0 || (events == 0 && oldestAge != 0) {
		return Backlog{}, ErrInvalidBacklog
	}
	return Backlog{events: events, oldestAge: oldestAge}, nil
}

// Events returns the number of events currently ready to be claimed.
func (backlog Backlog) Events() int64 {
	return backlog.events
}

// OldestAge returns how long the oldest ready event has been available.
func (backlog Backlog) OldestAge() time.Duration {
	return backlog.oldestAge
}

func (backlog Backlog) isValid() bool {
	return backlog.events >= 0 && backlog.oldestAge >= 0 &&
		(backlog.events != 0 || backlog.oldestAge == 0)
}

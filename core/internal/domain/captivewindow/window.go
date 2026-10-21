// Package captivewindow is the audit record of a captive portal window a
// Device's root opened to sign in to a hotel or airport Wi-Fi while it uses
// an exit node (exit node design §17.12, C6): when it opened and closed and
// how it ended, never the portal's address.
package captivewindow

import (
	"context"
	"errors"
	"regexp"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

// ErrInvalid reports a window no Device could have had.
var ErrInvalid = errors.New("captive window: invalid")

const (
	// MaximumPerReport bounds the windows of one report.
	MaximumPerReport = 16
	// MaximumLength is the longest window, the clients' cap with slack for
	// clocks.
	MaximumLength = 6 * time.Minute
	// MaximumAge bounds how old a reported window may be.
	MaximumAge = 30 * 24 * time.Hour
)

// End is how a window ended.
type End string

const (
	// EndExpired is a window whose time ran out.
	EndExpired End = "expired"
	// EndClosed is a window root closed, or that closed as the host stopped
	// using the exit node or the pool turned windows off.
	EndClosed End = "closed"
	// EndTunnelBack is a window meshd closed once the tunnel was back.
	EndTunnelBack End = "tunnel_back"
)

var windowID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidID reports an ID of the helper's shape: 32 lowercase hex digits.
func ValidID(id string) bool { return windowID.MatchString(id) }

// Window is one captive portal window as its Device reported it.
type Window struct {
	ID       string
	OpenedAt time.Time
	ClosedAt time.Time
	End      End
}

// Validate accepts a window with the helper's ID shape, a known end, and
// times no later than now, at most MaximumLength apart and MaximumAge old.
func (window Window) Validate(now time.Time) error {
	if !windowID.MatchString(window.ID) || window.OpenedAt.IsZero() || window.ClosedAt.Before(window.OpenedAt) ||
		window.ClosedAt.Sub(window.OpenedAt) > MaximumLength || window.ClosedAt.After(now.Add(time.Minute)) ||
		window.OpenedAt.Before(now.Add(-MaximumAge)) ||
		(window.End != EndExpired && window.End != EndClosed && window.End != EndTunnelBack) {
		return ErrInvalid
	}
	return nil
}

// Outcome is what recording one window did.
type Outcome uint8

const (
	// OutcomeAudited means the window is recorded with its audit event.
	OutcomeAudited Outcome = iota + 1
	// OutcomeKnown means the Device reported the window before.
	OutcomeKnown
	// OutcomeLimited means the Device reached its daily budget.
	OutcomeLimited
	// OutcomeBusy means another session of the Device is recording; the
	// Device reports again later.
	OutcomeBusy
)

// Recorder records the windows a Device of scope reported.
type Recorder interface {
	Record(ctx context.Context, scope network.Scope, device node.ID, window Window) (Outcome, error)
}

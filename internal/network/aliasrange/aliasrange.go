// Package aliasrange lets a receiving Network choose where Devices shared
// into it appear (R1-66). A range is a prefix inside the Deployment's
// Resource Alias frame, per address family; without one the whole frame is
// used. PostgreSQL checks network.read or network.update, the frame and the
// aliases already retained; this package validates shapes and receipts and
// never retries an uncertain commit.
package aliasrange

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

var (
	// ErrInvalid reports a malformed request or durable result.
	ErrInvalid = errors.New("network alias range: invalid request or result")
	// ErrForbidden conceals missing authority or an unavailable Network.
	ErrForbidden = errors.New("network alias range: permission denied")
	// ErrOutsideFrame reports a prefix outside the Deployment frame.
	ErrOutsideFrame = errors.New("network alias range: prefix outside the frame")
	// ErrInUse reports a change that would exclude an alias still retained.
	ErrInUse = errors.New("network alias range: retained alias outside the range")
	// ErrVersionConflict reports a stale expected version.
	ErrVersionConflict = errors.New("network alias range: version conflict")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("network alias range: unavailable")
)

// Prefix length bounds per family; PostgreSQL enforces the same.
const (
	MinIPv4Bits = 16
	MaxIPv4Bits = 28
	MinIPv6Bits = 96
	MaxIPv6Bits = 124
)

// ShareLimit is the number of live shares one map may project; schema 93
// and the supported client both stop at it.
const ShareLimit = 256

// ValidIPv4Range reports a canonical, correctly sized IPv4 prefix.
func ValidIPv4Range(prefix netip.Prefix) bool {
	return prefix.IsValid() && prefix.Addr().Is4() && prefix == prefix.Masked() &&
		prefix.Bits() >= MinIPv4Bits && prefix.Bits() <= MaxIPv4Bits
}

// ValidIPv6Range reports a canonical, correctly sized native IPv6 prefix.
func ValidIPv6Range(prefix netip.Prefix) bool {
	return prefix.IsValid() && prefix.Addr().Is6() && !prefix.Addr().Is4In6() &&
		prefix == prefix.Masked() && prefix.Bits() >= MinIPv6Bits && prefix.Bits() <= MaxIPv6Bits
}

// Change is one family's requested range. An absent change leaves the family
// unchanged; a present change with the zero prefix returns it to the frame.
type Change struct {
	Present bool
	Prefix  netip.Prefix
}

func (change Change) valid(family int) bool {
	if !change.Present {
		return change.Prefix == netip.Prefix{}
	}
	if change.Prefix == (netip.Prefix{}) {
		return true
	}
	if family == 4 {
		return ValidIPv4Range(change.Prefix)
	}
	return ValidIPv6Range(change.Prefix)
}

// Command updates the ranges of one exact Network.
type Command struct {
	Session         accountsession.Session
	Scope           network.Scope
	ExpectedVersion int64
	IPv4            Change
	IPv6            Change
	CorrelationID   publicid.ID
}

// IsValid checks shape; at least one family must change.
func (command Command) IsValid() bool {
	return command.Session.IsValid() && command.Scope.IsValid() && command.ExpectedVersion > 0 &&
		(command.IPv4.Present || command.IPv6.Present) && command.IPv4.valid(4) && command.IPv6.valid(6) &&
		command.CorrelationID.IsValid()
}

// Family is the frame, chosen range and usage of one address family.
type Family struct {
	Family int
	// Frame is the Deployment's Resource Alias pool; zero when none is active.
	Frame netip.Prefix
	// Prefix is the chosen range; zero means the whole frame.
	Prefix netip.Prefix
	// Retained counts aliases this Network holds as the receiving side,
	// including quarantined ones that are not yet reusable.
	Retained int64
}

// State is the current alias range state of one Network.
type State struct {
	Version    int64
	IPv4, IPv6 Family
	// LiveShares counts shares currently projected into the Network.
	LiveShares int64
	ShareLimit int64
}

// IsValid checks a durable state.
func (state State) IsValid() bool {
	return state.Version > 0 && state.IPv4.valid(4) && state.IPv6.valid(6) &&
		state.LiveShares >= 0 && state.ShareLimit > 0
}

func (family Family) valid(number int) bool {
	if family.Family != number || family.Retained < 0 {
		return false
	}
	if family.Frame != (netip.Prefix{}) && (!family.Frame.IsValid() || family.Frame != family.Frame.Masked() ||
		family.Frame.Addr().Is4() != (number == 4)) {
		return false
	}
	if family.Prefix == (netip.Prefix{}) {
		return true
	}
	return (Change{Present: true, Prefix: family.Prefix}).valid(number) &&
		family.Frame.IsValid() && family.Frame.Bits() <= family.Prefix.Bits() && family.Frame.Contains(family.Prefix.Addr())
}

// Result is the committed state; Changed is false when the request matched
// the current ranges and nothing was written.
type Result struct {
	State   State
	Changed bool
}

func (result Result) matches(command Command) bool {
	if !result.State.IsValid() {
		return false
	}
	if command.IPv4.Present && result.State.IPv4.Prefix != command.IPv4.Prefix {
		return false
	}
	if command.IPv6.Present && result.State.IPv6.Prefix != command.IPv6.Prefix {
		return false
	}
	if result.Changed {
		return result.State.Version > command.ExpectedVersion
	}
	return result.State.Version == command.ExpectedVersion
}

// Store reads and commits with fresh authority and audit evidence.
type Store interface {
	Read(context.Context, accountsession.Session, network.Scope, time.Time) (State, error)
	Update(context.Context, Command, time.Time) (Result, error)
}

// Clock supplies the application admission instant.
type Clock interface{ Now() time.Time }

// Service validates requests and receipts.
type Service struct {
	store Store
	clock Clock
}

// NewService validates explicit dependencies.
func NewService(store Store, clock Clock) (*Service, error) {
	if store == nil || clock == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, clock: clock}, nil
}

func (service *Service) admit(ctx context.Context, session accountsession.Session) (time.Time, error) {
	if ctx == nil || service == nil || service.store == nil || service.clock == nil {
		return time.Time{}, ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return time.Time{}, ErrForbidden
	}
	return now, nil
}

// Read returns the ranges of one Network for an active Session.
func (service *Service) Read(ctx context.Context, session accountsession.Session, scope network.Scope) (State, error) {
	if !session.IsValid() || !scope.IsValid() {
		return State{}, ErrInvalid
	}
	now, err := service.admit(ctx, session)
	if err != nil {
		return State{}, err
	}
	state, err := service.store.Read(ctx, session, scope, now)
	if err != nil {
		return State{}, err
	}
	if !state.IsValid() {
		return State{}, ErrInvalid
	}
	return state, nil
}

// Update commits the requested ranges and returns the durable state.
func (service *Service) Update(ctx context.Context, command Command) (Result, error) {
	if !command.IsValid() {
		return Result{}, ErrInvalid
	}
	now, err := service.admit(ctx, command.Session)
	if err != nil {
		return Result{}, err
	}
	result, err := service.store.Update(ctx, command, now)
	if err != nil {
		return Result{}, err
	}
	if !result.matches(command) {
		return Result{}, ErrInvalid
	}
	return result, nil
}

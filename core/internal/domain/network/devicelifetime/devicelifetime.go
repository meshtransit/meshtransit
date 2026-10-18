// Package devicelifetime lets a Network choose how long a Device that signs
// in through the browser lives: a fixed time between one hour and 180 days,
// or never expiring. Without a choice a Device lives 180 days. The choice
// applies from the next sign-in; Devices already registered keep their
// expiry until then. PostgreSQL checks network.read or network.update; this
// package validates shapes and receipts and never retries an uncertain
// commit.
package devicelifetime

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

var (
	// ErrInvalid reports a malformed request or durable result.
	ErrInvalid = errors.New("network device lifetime: invalid request or result")
	// ErrForbidden conceals missing authority or an unavailable Network.
	ErrForbidden = errors.New("network device lifetime: permission denied")
	// ErrNoInteractiveProfile reports a Network nobody can sign in to.
	ErrNoInteractiveProfile = errors.New("network device lifetime: no interactive enrollment")
	// ErrVersionConflict reports a stale expected version.
	ErrVersionConflict = errors.New("network device lifetime: version conflict")
	// ErrUnavailable reports an unavailable or uncertain durable operation.
	ErrUnavailable = errors.New("network device lifetime: unavailable")
)

// State is the Device lifetime of one Network.
type State struct {
	Version int64
	// Lifetime is how long a signed-in Device lives; zero when it never
	// expires.
	Lifetime time.Duration
	// NeverExpires is true when signed-in Devices never expire.
	NeverExpires bool
	// Default is true while the Network has chosen nothing.
	Default bool
}

// IsValid checks a durable state.
func (state State) IsValid() bool {
	if state.Version <= 0 {
		return false
	}
	if state.NeverExpires {
		return state.Lifetime == 0 && !state.Default
	}
	if state.Default {
		// A profile made before the choice existed keeps its own lifetime.
		return state.Lifetime > 0
	}
	_, err := enrollment.NewDeviceLifetime(state.Lifetime)
	return err == nil
}

// Command sets the Device lifetime of one exact Network.
type Command struct {
	Session         accountsession.Session
	Scope           network.Scope
	ExpectedVersion int64
	// Lifetime is a fixed lifetime; ignored when NeverExpires.
	Lifetime      time.Duration
	NeverExpires  bool
	CorrelationID publicid.ID
}

// IsValid checks shape: a fixed lifetime in bounds, or never with none.
func (command Command) IsValid() bool {
	if !command.Session.IsValid() || !command.Scope.IsValid() || command.ExpectedVersion <= 0 ||
		!command.CorrelationID.IsValid() {
		return false
	}
	if command.NeverExpires {
		return command.Lifetime == 0
	}
	_, err := enrollment.NewDeviceLifetime(command.Lifetime)
	return err == nil
}

// Result is the committed state; Changed is false when the request matched
// the current choice and nothing was written.
type Result struct {
	State   State
	Changed bool
}

func (result Result) matches(command Command) bool {
	state := result.State
	if !state.IsValid() || state.Default || state.NeverExpires != command.NeverExpires ||
		(!command.NeverExpires && state.Lifetime != command.Lifetime) {
		return false
	}
	if result.Changed {
		return state.Version > command.ExpectedVersion
	}
	return state.Version == command.ExpectedVersion
}

// Store reads and commits with fresh authority and audit evidence. It
// authorizes and stamps each call on the database clock.
type Store interface {
	Read(context.Context, accountsession.Session, network.Scope) (State, error)
	Update(context.Context, Command) (Result, error)
}

// Clock supplies this host's time for the early session gate only.
type Clock interface{ Now() time.Time }

// Service validates requests and results.
type Service struct {
	store Store
	clock Clock
}

// NewService returns a Service over store.
func NewService(store Store, clock Clock) (*Service, error) {
	if store == nil || clock == nil {
		return nil, ErrInvalid
	}
	return &Service{store: store, clock: clock}, nil
}

// admit is an early, fail-closed gate on this host's clock: it can only deny.
// PostgreSQL authorizes the call on the database clock.
func (service *Service) admit(ctx context.Context, session accountsession.Session) error {
	if ctx == nil || service == nil || service.store == nil || service.clock == nil {
		return ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return ErrForbidden
	}
	return nil
}

// Read returns the Device lifetime of one Network for an active Session.
func (service *Service) Read(ctx context.Context, session accountsession.Session, scope network.Scope) (State, error) {
	if !session.IsValid() || !scope.IsValid() {
		return State{}, ErrInvalid
	}
	if err := service.admit(ctx, session); err != nil {
		return State{}, err
	}
	state, err := service.store.Read(ctx, session, scope)
	if err != nil {
		return State{}, err
	}
	if !state.IsValid() {
		return State{}, ErrInvalid
	}
	return state, nil
}

// Update commits the requested lifetime and returns the durable state.
func (service *Service) Update(ctx context.Context, command Command) (Result, error) {
	if !command.IsValid() {
		return Result{}, ErrInvalid
	}
	if err := service.admit(ctx, command.Session); err != nil {
		return Result{}, err
	}
	result, err := service.store.Update(ctx, command)
	if err != nil {
		return Result{}, err
	}
	if !result.matches(command) {
		return Result{}, ErrInvalid
	}
	return result, nil
}

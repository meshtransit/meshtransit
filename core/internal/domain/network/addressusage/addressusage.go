// Package addressusage reports how full a Network's address ranges are.
package addressusage

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
)

var (
	// ErrInvalid reports a malformed request or result.
	ErrInvalid = errors.New("network address usage: invalid request or result")
	// ErrForbidden reports a Session without network.read on the Network.
	ErrForbidden = errors.New("network address usage: permission denied")
	// ErrUnavailable reports a store failure.
	ErrUnavailable = errors.New("network address usage: unavailable")
)

// maxPrefixes bounds the ranges of one Network (registration allows 8).
const maxPrefixes = 8

// Range is the use of one address range of the Network.
type Range struct {
	Prefix netip.Prefix
	// Capacity is the number of addresses Devices can get; zero when the
	// range cannot run out (IPv6 /95 or wider).
	Capacity int64
	// InUse counts addresses of Devices that have not expired.
	InUse int64
	// HeldByExpired counts addresses expired Devices still hold.
	HeldByExpired int64
	// HeldAfterRevocation counts addresses of revoked Devices held back for
	// a day; NextRelease is when the first of them can be given out again.
	HeldAfterRevocation int64
	NextRelease         time.Time
}

func (usage Range) valid() bool {
	if !usage.Prefix.IsValid() || usage.Prefix != usage.Prefix.Masked() || usage.InUse < 0 ||
		usage.HeldByExpired < 0 || usage.HeldAfterRevocation < 0 ||
		usage.NextRelease.IsZero() != (usage.HeldAfterRevocation == 0) {
		return false
	}
	taken := usage.InUse + usage.HeldByExpired + usage.HeldAfterRevocation
	if usage.Prefix.Addr().Is6() && usage.Prefix.Bits() < 96 {
		return usage.Capacity == 0
	}
	return usage.Capacity > 0 && usage.Capacity >= taken
}

// State is the use of every address range of one Network.
type State struct {
	Ranges []Range
}

// IsValid requires at least one range and at most maxPrefixes, each sound.
func (state State) IsValid() bool {
	if len(state.Ranges) == 0 || len(state.Ranges) > maxPrefixes {
		return false
	}
	for _, usage := range state.Ranges {
		if !usage.valid() {
			return false
		}
	}
	return true
}

// Store reads the use under fresh authority.
type Store interface {
	Read(context.Context, accountsession.Session, network.Scope, time.Time) (State, error)
}

// Clock supplies the application admission instant.
type Clock interface{ Now() time.Time }

// Service validates requests and results.
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

// Read returns the use of one Network's ranges for an active Session.
func (service *Service) Read(ctx context.Context, session accountsession.Session, scope network.Scope) (State, error) {
	if ctx == nil || service == nil || service.store == nil || service.clock == nil ||
		!session.IsValid() || !scope.IsValid() {
		return State{}, ErrInvalid
	}
	now := service.clock.Now().UTC()
	if now.IsZero() || !session.IsActiveAt(now) {
		return State{}, ErrForbidden
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

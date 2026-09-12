package app

import (
	"errors"
	"sync/atomic"
)

var (
	// ErrInvalidRuntimeState indicates missing or invalid active roles.
	ErrInvalidRuntimeState = errors.New("invalid runtime state")
)

// RuntimeState is the concurrency-safe admission state exposed to operational
// adapters. It owns a defensive copy of the active concrete roles.
type RuntimeState struct {
	ready atomic.Bool
	roles []Role
}

// NewRuntimeState constructs a closed admission gate for concrete active roles.
func NewRuntimeState(roles []Role) (*RuntimeState, error) {
	if err := validateActiveRoles(roles); err != nil {
		return nil, errors.Join(ErrInvalidRuntimeState, err)
	}
	return &RuntimeState{roles: append([]Role(nil), roles...)}, nil
}

// SetReady changes whether the process may admit its configured work.
func (state *RuntimeState) SetReady(ready bool) {
	state.ready.Store(ready)
}

// Ready reports whether the process may admit its configured work.
func (state *RuntimeState) Ready() bool {
	return state.ready.Load()
}

// Roles returns a caller-owned list of active role names.
func (state *RuntimeState) Roles() []string {
	return roleNames(state.roles)
}

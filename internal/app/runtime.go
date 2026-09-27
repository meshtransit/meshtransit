package app

import (
	"errors"
	"sync"
	"sync/atomic"
)

var (
	// ErrInvalidRuntimeState indicates missing or invalid active roles.
	ErrInvalidRuntimeState = errors.New("invalid runtime state")
)

// RuntimeState is the concurrency-safe admission state exposed to operational
// adapters. It owns a defensive copy of the active concrete roles.
type RuntimeState struct {
	admission         atomic.Bool
	roles             []Role
	required          []Component
	admissionRequired map[Component]struct{}
	loginConfigured   bool

	mu       sync.RWMutex
	statuses map[Component]ComponentStatus
}

// ComponentStatus is one bounded, operator-safe dependency state.
type ComponentStatus uint8

const (
	// ComponentStatusUnknown means no completed check is available yet.
	ComponentStatusUnknown ComponentStatus = iota
	// ComponentStatusReady means the last bounded check succeeded.
	ComponentStatusReady
	// ComponentStatusUnavailable means the last bounded check failed.
	ComponentStatusUnavailable
)

// String returns the stable operator-facing dependency state.
func (status ComponentStatus) String() string {
	switch status {
	case ComponentStatusReady:
		return "ready"
	case ComponentStatusUnavailable:
		return "unavailable"
	default:
		return "unknown"
	}
}

// HealthSnapshot is a caller-owned, redacted operational state snapshot.
type HealthSnapshot struct {
	Ready           bool
	LoginConfigured bool
	LoginReady      bool
	Roles           []string
	Components      map[string]string
}

// NewRuntimeState constructs a closed admission gate for concrete active roles.
// The only optional component is private login, scoped to an API process. It is
// not a public-login qualification flag or an arbitrary component registry.
func NewRuntimeState(roles []Role, optional ...Component) (*RuntimeState, error) {
	required, err := RequiredComponents(roles)
	if err != nil {
		return nil, errors.Join(ErrInvalidRuntimeState, err)
	}
	if len(optional) > 1 {
		return nil, ErrInvalidRuntimeState
	}
	loginConfigured := len(optional) == 1
	if loginConfigured {
		if optional[0] != ComponentPrivateLogin || !hasAPIRole(roles) {
			return nil, ErrInvalidRuntimeState
		}
		required = append(required, ComponentPrivateLogin)
	}
	admissionRequired := make(map[Component]struct{}, len(required))
	isolateIdentity := hasAPIRole(roles) && hasIdentityRole(roles)
	for _, component := range required {
		if component == ComponentPrivateLogin || isolateIdentity && isIdentityComponent(component) {
			continue
		}
		admissionRequired[component] = struct{}{}
	}
	statuses := make(map[Component]ComponentStatus, len(required))
	for _, component := range required {
		statuses[component] = ComponentStatusUnknown
	}
	return &RuntimeState{
		roles:             append([]Role(nil), roles...),
		required:          append([]Component(nil), required...),
		admissionRequired: admissionRequired,
		loginConfigured:   loginConfigured,
		statuses:          statuses,
	}, nil
}

func hasAPIRole(roles []Role) bool {
	for _, role := range roles {
		if role == RoleAPI {
			return true
		}
	}
	return false
}

func hasIdentityRole(roles []Role) bool {
	for _, role := range roles {
		if role == RoleIdentity {
			return true
		}
	}
	return false
}

func isIdentityComponent(component Component) bool {
	return component == ComponentIdentityPostgreSQL || component == ComponentIdentityConfiguration ||
		component == ComponentIdentitySigner
}

// SetReady changes whether the process may admit its configured work.
func (state *RuntimeState) SetReady(ready bool) {
	state.admission.Store(ready)
}

// Ready reports whether the process may admit its configured work.
func (state *RuntimeState) Ready() bool {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.readyLocked()
}

// Roles returns a caller-owned list of active role names.
func (state *RuntimeState) Roles() []string {
	return roleNames(state.roles)
}

// RequiredComponents returns a caller-owned list of required dependency IDs.
func (state *RuntimeState) RequiredComponents() []Component {
	return append([]Component(nil), state.required...)
}

// AdmissionRequired reports whether a monitored component gates the general
// Core readiness endpoint. Login-only dependencies remain observable without
// evicting healthy API, control, worker, or relay traffic.
func (state *RuntimeState) AdmissionRequired(component Component) bool {
	_, required := state.admissionRequired[component]
	return required
}

// SetComponentStatus atomically updates one required dependency state.
func (state *RuntimeState) SetComponentStatus(component Component, status ComponentStatus) error {
	return state.SetComponentStatuses(map[Component]ComponentStatus{component: status})
}

// SetComponentStatuses validates every update before applying the batch.
func (state *RuntimeState) SetComponentStatuses(updates map[Component]ComponentStatus) error {
	if len(updates) == 0 {
		return ErrInvalidRuntimeState
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	for component, status := range updates {
		if _, required := state.statuses[component]; !required || !validComponentStatus(status) {
			return ErrInvalidRuntimeState
		}
	}
	for component, status := range updates {
		state.statuses[component] = status
	}
	return nil
}

// Snapshot returns a consistent, caller-owned, redacted health view.
func (state *RuntimeState) Snapshot() HealthSnapshot {
	state.mu.RLock()
	defer state.mu.RUnlock()

	components := make(map[string]string, len(state.required))
	for _, component := range state.required {
		components[component.String()] = state.statuses[component].String()
	}
	return HealthSnapshot{
		Ready:           state.readyLocked(),
		LoginConfigured: state.loginConfigured,
		LoginReady:      state.loginReadyLocked(),
		Roles:           roleNames(state.roles),
		Components:      components,
	}
}

func (state *RuntimeState) readyLocked() bool {
	if !state.admission.Load() {
		return false
	}
	for component := range state.admissionRequired {
		if state.statuses[component] != ComponentStatusReady {
			return false
		}
	}
	return true
}

func (state *RuntimeState) loginReadyLocked() bool {
	if !state.loginConfigured || !state.admission.Load() {
		return false
	}
	for _, component := range state.required {
		if state.statuses[component] != ComponentStatusReady {
			return false
		}
	}
	return true
}

func validComponentStatus(status ComponentStatus) bool {
	return status == ComponentStatusReady || status == ComponentStatusUnavailable
}

// Package app owns process-level role selection and lifecycle orchestration.
package app

import "errors"

// ErrInvalidRole indicates an unknown or unusable runtime role.
var ErrInvalidRole = errors.New("invalid runtime role")

// Role identifies one closed set of process responsibilities.
type Role uint8

const (
	// RoleUnknown is the invalid zero value.
	RoleUnknown Role = iota
	// RoleAll enables every independently scalable runtime responsibility.
	RoleAll
	// RoleAPI enables management and identity-facing HTTP responsibilities.
	RoleAPI
	// RoleControl enables client trust, registration, and map responsibilities.
	RoleControl
	// RoleWorker enables bounded durable background work.
	RoleWorker
	// RoleRelay enables the packet relay responsibility.
	RoleRelay
	// RoleIdentity enables the isolated embedded identity broker responsibility.
	RoleIdentity
)

// ParseRole parses one exact, canonical runtime role name.
func ParseRole(value string) (Role, error) {
	switch value {
	case "all":
		return RoleAll, nil
	case "api":
		return RoleAPI, nil
	case "control":
		return RoleControl, nil
	case "worker":
		return RoleWorker, nil
	case "relay":
		return RoleRelay, nil
	case "identity":
		return RoleIdentity, nil
	default:
		return RoleUnknown, ErrInvalidRole
	}
}

// String returns the canonical runtime role name.
func (role Role) String() string {
	switch role {
	case RoleAll:
		return "all"
	case RoleAPI:
		return "api"
	case RoleControl:
		return "control"
	case RoleWorker:
		return "worker"
	case RoleRelay:
		return "relay"
	case RoleIdentity:
		return "identity"
	default:
		return "unknown"
	}
}

// ExpandRole returns the concrete responsibilities enabled by role.
// The returned slice is owned by the caller.
func ExpandRole(role Role) ([]Role, error) {
	switch role {
	case RoleAll:
		return []Role{RoleAPI, RoleControl, RoleWorker, RoleRelay, RoleIdentity}, nil
	case RoleAPI, RoleControl, RoleWorker, RoleRelay, RoleIdentity:
		return []Role{role}, nil
	default:
		return nil, ErrInvalidRole
	}
}

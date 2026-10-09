package authorization

import (
	"errors"
	"time"
)

var (
	// ErrInvalidAuthorityGeneration reports an absent authority generation.
	ErrInvalidAuthorityGeneration = errors.New("authorization: invalid authority generation")
	// ErrInvalidGrantState reports an unknown grant lifecycle state.
	ErrInvalidGrantState = errors.New("authorization: invalid grant state")
)

// AuthorityGeneration is a monotonic authorization snapshot generation.
type AuthorityGeneration uint64

// GrantState identifies whether a resolved role grant remains active.
type GrantState uint8

const (
	// GrantUnknown is the invalid zero-value grant state.
	GrantUnknown GrantState = iota
	// GrantActive permits evaluation when every other check succeeds.
	GrantActive
	// GrantRevoked preserves revocation evidence but never authorizes.
	GrantRevoked
)

// GrantOptions contains validated server-side role expansion input.
type GrantOptions struct {
	// PrincipalID is the stable Core principal receiving the resolved grant.
	PrincipalID PrincipalID
	// Permission is one exact permission from the approved catalog.
	Permission Permission
	// Scope is the binding's fully qualified authority scope.
	Scope Scope
	// AuthorityGeneration binds the grant to one authority snapshot.
	AuthorityGeneration AuthorityGeneration
	// State is the current durable grant lifecycle state.
	State GrantState
	// ExpiresAt is an optional exclusive expiry boundary; zero means no expiry.
	ExpiresAt time.Time
}

// Grant is an immutable permission resolved from Core-owned role authority.
type Grant struct {
	principalID         PrincipalID
	permission          Permission
	scope               Scope
	authorityGeneration AuthorityGeneration
	state               GrantState
	expiresAt           time.Time
}

// NewGrant validates a server-side resolved grant and returns an immutable value.
func NewGrant(options GrantOptions) (Grant, error) {
	if !options.PrincipalID.isValid() {
		return Grant{}, ErrInvalidPublicID
	}
	definition, ok := LookupPermission(options.Permission)
	if !ok {
		return Grant{}, ErrUnknownPermission
	}
	if !options.Scope.isValid() || !definition.allowsBinding(options.Scope.kind) {
		return Grant{}, ErrInvalidScope
	}
	if options.AuthorityGeneration == 0 {
		return Grant{}, ErrInvalidAuthorityGeneration
	}
	if options.State != GrantActive && options.State != GrantRevoked {
		return Grant{}, ErrInvalidGrantState
	}
	return Grant{
		principalID:         options.PrincipalID,
		permission:          options.Permission,
		scope:               options.Scope,
		authorityGeneration: options.AuthorityGeneration,
		state:               options.State,
		expiresAt:           options.ExpiresAt.UTC(),
	}, nil
}

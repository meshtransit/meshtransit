package authorization

import (
	"errors"
	"time"
)

// ErrInvalidEvaluationTime reports an absent evaluation timestamp.
var ErrInvalidEvaluationTime = errors.New("authorization: invalid evaluation time")

// RequestOptions contains one authenticated, server-scoped RBAC evaluation request.
type RequestOptions struct {
	// PrincipalID is the authenticated stable Core principal.
	PrincipalID PrincipalID
	// Permission is the exact operation permission being checked.
	Permission Permission
	// Target is the server-derived fully qualified operation scope.
	Target Scope
	// AuthorityGeneration is the current authoritative scope generation.
	AuthorityGeneration AuthorityGeneration
	// EvaluatedAt is the injected authorization time.
	EvaluatedAt time.Time
}

// Request is an immutable scoped authorization evaluation input.
type Request struct {
	principalID         PrincipalID
	permission          Permission
	target              Scope
	authorityGeneration AuthorityGeneration
	evaluatedAt         time.Time
}

// NewRequest validates an authenticated and server-scoped evaluation request.
func NewRequest(options RequestOptions) (Request, error) {
	if !options.PrincipalID.isValid() {
		return Request{}, ErrInvalidPublicID
	}
	definition, ok := LookupPermission(options.Permission)
	if !ok {
		return Request{}, ErrUnknownPermission
	}
	if !options.Target.isValid() || !definition.allowsTarget(options.Target.kind) {
		return Request{}, ErrInvalidScope
	}
	if options.AuthorityGeneration == 0 {
		return Request{}, ErrInvalidAuthorityGeneration
	}
	if options.EvaluatedAt.IsZero() {
		return Request{}, ErrInvalidEvaluationTime
	}
	return Request{
		principalID:         options.PrincipalID,
		permission:          options.Permission,
		target:              options.Target,
		authorityGeneration: options.AuthorityGeneration,
		evaluatedAt:         options.EvaluatedAt.UTC(),
	}, nil
}

func (r Request) isValid() bool {
	definition, ok := LookupPermission(r.permission)
	return r.principalID.isValid() && ok && r.target.isValid() &&
		definition.allowsTarget(r.target.kind) && r.authorityGeneration > 0 &&
		!r.evaluatedAt.IsZero()
}

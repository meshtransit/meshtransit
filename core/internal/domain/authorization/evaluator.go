package authorization

// MaxEvaluatedGrants bounds the work performed for one authorization decision.
const MaxEvaluatedGrants = 256

// Reason is a stable internal authorization decision classification.
type Reason uint8

const (
	// ReasonUnknown is the invalid zero-value reason.
	ReasonUnknown Reason = iota
	// ReasonAllowed means one current active grant matched exactly.
	ReasonAllowed
	// ReasonInvalidRequest means the evaluation input was not constructible authority data.
	ReasonInvalidRequest
	// ReasonGrantSetTooLarge means the bounded evaluator refused excessive work.
	ReasonGrantSetTooLarge
	// ReasonNoMatchingGrant means no grant matched principal, permission, and scope.
	ReasonNoMatchingGrant
	// ReasonInactiveGrant means only revoked matching authority was present.
	ReasonInactiveGrant
	// ReasonExpiredGrant means only expired matching authority was present.
	ReasonExpiredGrant
	// ReasonStaleGeneration means matching authority belonged to a stale generation.
	ReasonStaleGeneration
)

// String returns the stable safe audit code for a decision reason.
func (r Reason) String() string {
	switch r {
	case ReasonAllowed:
		return "allowed"
	case ReasonInvalidRequest:
		return "invalid_request"
	case ReasonGrantSetTooLarge:
		return "grant_set_too_large"
	case ReasonNoMatchingGrant:
		return "no_matching_grant"
	case ReasonInactiveGrant:
		return "inactive_grant"
	case ReasonExpiredGrant:
		return "expired_grant"
	case ReasonStaleGeneration:
		return "stale_generation"
	default:
		return "unknown"
	}
}

// Decision is an immutable scoped-grant outcome.
//
// An allowed decision covers only the RBAC grant step. Callers must still apply
// operation invariants, approval policy, step-up, and optimistic concurrency.
type Decision struct {
	reason Reason
}

// IsAllowed reports whether an active current grant matched the exact request.
func (d Decision) IsAllowed() bool { return d.reason == ReasonAllowed }

// Reason returns the stable internal decision classification.
func (d Decision) Reason() Reason { return d.reason }

// Evaluate checks a bounded set of Core-owned resolved grants and fails closed.
func Evaluate(request Request, grants []Grant) Decision {
	if !request.isValid() {
		return Decision{reason: ReasonInvalidRequest}
	}
	if len(grants) > MaxEvaluatedGrants {
		return Decision{reason: ReasonGrantSetTooLarge}
	}

	definition, _ := LookupPermission(request.permission)
	reason := ReasonNoMatchingGrant
	for _, grant := range grants {
		if grant.principalID != request.principalID || grant.permission != request.permission ||
			!definition.Applies(grant.scope, request.target) {
			continue
		}
		if grant.state != GrantActive {
			reason = strongerDenial(reason, ReasonInactiveGrant)
			continue
		}
		if grant.authorityGeneration != request.authorityGeneration {
			reason = strongerDenial(reason, ReasonStaleGeneration)
			continue
		}
		if !grant.expiresAt.IsZero() && !request.evaluatedAt.Before(grant.expiresAt) {
			reason = strongerDenial(reason, ReasonExpiredGrant)
			continue
		}
		return Decision{reason: ReasonAllowed}
	}
	return Decision{reason: reason}
}

func strongerDenial(current Reason, candidate Reason) Reason {
	if denialPriority(candidate) > denialPriority(current) {
		return candidate
	}
	return current
}

func denialPriority(reason Reason) uint8 {
	switch reason {
	case ReasonNoMatchingGrant:
		return 1
	case ReasonInactiveGrant:
		return 2
	case ReasonExpiredGrant:
		return 3
	case ReasonStaleGeneration:
		return 4
	default:
		return 0
	}
}

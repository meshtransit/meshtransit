package intake

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
)

// Transactions starts explicit registration-intake units of work.
type Transactions interface {
	Begin(context.Context, Lookup) (Transaction, error)
}

// Transaction resolves server authority under lock and applies at most one
// pending-intent mutation. The application owns commit and rollback decisions.
type Transaction interface {
	// DecisionTime is the database clock's time for this transaction: every
	// evaluation and persisted time of the attempt uses it.
	DecisionTime() time.Time
	Resolve(context.Context, Lookup) (Resolution, error)
	Apply(context.Context, Change) error
	Commit(context.Context) error
	Rollback(context.Context) error
}

// PreparedIntentResolver resolves an uncertain commit from authoritative replay evidence.
type PreparedIntentResolver interface {
	ResolvePrepared(context.Context, registration.Command) (registration.RequestHash, bool, error)
}

// CredentialVerifier verifies a versioned credential digest in constant time.
type CredentialVerifier interface {
	Verify(
		deployment.ID,
		int64,
		enrollment.CredentialToken,
		enrollment.CredentialDigest,
	) bool
}

// EvidenceIDGenerator creates one immutable identity set for a pending-intent mutation.
type EvidenceIDGenerator interface {
	NewEvidenceIDs() (EvidenceIDs, error)
}

// RetryWaiter applies bounded backoff between complete transaction attempts.
type RetryWaiter interface {
	Wait(context.Context, int) error
}

// Dependencies contains the explicit ports required by Service. None may retain
// request context or start background work.
type Dependencies struct {
	Transactions     Transactions
	PreparedIntents  PreparedIntentResolver
	CredentialProofs CredentialVerifier
	EvidenceIDs      EvidenceIDGenerator
	Retry            RetryWaiter
}

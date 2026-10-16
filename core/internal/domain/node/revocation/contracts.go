package revocation

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/network"
)

// Transactions starts explicit Device revocation units of work.
type Transactions interface {
	Begin(context.Context, network.Scope) (Transaction, error)
}

// Transaction is one short revocation unit with application-owned completion.
type Transaction interface {
	// DecisionTime is the database clock's time for this transaction: every
	// evaluation and persisted time of the attempt uses it.
	DecisionTime() time.Time
	Resolve(context.Context, Command, Attempt) (Resolution, error)
	Apply(context.Context, Change) (Result, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// CommittedResultResolver resolves an uncertain commit from durable idempotency evidence.
type CommittedResultResolver interface {
	// ResolveCommitted judges replay evidence on its own transaction's
	// database time.
	ResolveCommitted(context.Context, Command, MutationIDs) (Result, bool, error)
}

// MutationIDGenerator creates stable public IDs once for all retry attempts.
type MutationIDGenerator interface {
	NewMutationIDs() (MutationIDs, error)
}

// RetryWaiter applies bounded delay between complete transaction attempts.
type RetryWaiter interface {
	Wait(context.Context, int) error
}

// Dependencies contains every explicit port required by Service.
type Dependencies struct {
	Transactions     Transactions
	CommittedResults CommittedResultResolver
	MutationIDs      MutationIDGenerator
	Retry            RetryWaiter
}

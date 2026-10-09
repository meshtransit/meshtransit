package publication

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/network"
)

// Transactions starts explicit packet-policy publication units of work.
type Transactions interface {
	Begin(context.Context, network.Scope) (Transaction, error)
}

// Transaction is one short activation unit. The application owns commit and rollback.
type Transaction interface {
	Resolve(context.Context, Command, time.Time) (Resolution, error)
	Apply(context.Context, Change) (Result, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// CommittedResultResolver resolves an uncertain commit by immutable release identity.
type CommittedResultResolver interface {
	ResolveCommitted(context.Context, Command, ReleaseID) (Result, bool, error)
}

// MutationIDGenerator creates stable public IDs once for all transaction attempts.
type MutationIDGenerator interface {
	NewMutationIDs(int) (MutationIDs, error)
}

// Clock supplies one stable decision time for every replayable attempt.
type Clock interface {
	Now() time.Time
}

// RetryWaiter applies bounded delay between complete transaction attempts.
type RetryWaiter interface {
	Wait(context.Context, int) error
}

// Dependencies contains all explicit ports required by Service.
type Dependencies struct {
	Transactions     Transactions
	CommittedResults CommittedResultResolver
	MutationIDs      MutationIDGenerator
	Clock            Clock
	Retry            RetryWaiter
}

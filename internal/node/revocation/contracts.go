package revocation

import (
	"context"
	"time"

	"github.com/meshtransit/meshtransit/internal/network"
)

// Transactions starts explicit Device revocation units of work.
type Transactions interface {
	Begin(context.Context, network.Scope) (Transaction, error)
}

// Transaction is one short revocation unit with application-owned completion.
type Transaction interface {
	Resolve(context.Context, Command, Attempt) (Resolution, error)
	Apply(context.Context, Change) (Result, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// CommittedResultResolver resolves an uncertain commit from durable idempotency evidence.
type CommittedResultResolver interface {
	ResolveCommitted(context.Context, Command) (Result, bool, error)
}

// MutationIDGenerator creates stable public IDs once for all retry attempts.
type MutationIDGenerator interface {
	NewMutationIDs() (MutationIDs, error)
}

// Clock supplies one stable decision time to the replayable operation.
type Clock interface {
	Now() time.Time
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
	Clock            Clock
	Retry            RetryWaiter
}

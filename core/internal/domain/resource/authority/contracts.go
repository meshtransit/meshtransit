package authority

import (
	"context"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/network"
)

// Transactions starts explicit Resource authority units of work.
type Transactions interface {
	Begin(context.Context, network.Scope) (Transaction, error)
}

// Transaction is one short mutation unit. The application owns completion.
type Transaction interface {
	Resolve(context.Context, Command, MutationIDs, time.Time, time.Time) (Resolution, error)
	Apply(context.Context, Change) (Result, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// CommittedResultResolver resolves uncertain commit outcomes by stable identity.
type CommittedResultResolver interface {
	ResolveCommitted(context.Context, Command, MutationIDs) (Result, bool, error)
}

// MutationIDGenerator allocates stable IDs once for all transaction attempts.
type MutationIDGenerator interface {
	NewMutationIDs(Command) (MutationIDs, error)
}

// Clock supplies one stable decision time for every replayable attempt.
type Clock interface{ Now() time.Time }

// RetryWaiter applies bounded delay between whole transaction attempts.
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

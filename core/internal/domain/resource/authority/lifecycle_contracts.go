package authority

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/network"
)

// LifecycleTransactions starts explicit Resource lifecycle units of work.
type LifecycleTransactions interface {
	BeginLifecycle(context.Context, network.Scope) (LifecycleTransaction, error)
}

// LifecycleTransaction is one short lifecycle mutation unit.
type LifecycleTransaction interface {
	Resolve(context.Context, LifecycleCommand, LifecycleMutationIDs, time.Time, time.Time) (LifecycleResolution, error)
	Apply(context.Context, LifecycleChange) (LifecycleResult, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// CommittedLifecycleResultResolver resolves uncertain commits by idempotency identity.
type CommittedLifecycleResultResolver interface {
	ResolveCommittedLifecycle(context.Context, LifecycleCommand, LifecycleMutationIDs) (LifecycleResult, bool, error)
}

// LifecycleMutationIDGenerator allocates stable IDs once for all transaction attempts.
type LifecycleMutationIDGenerator interface {
	NewLifecycleMutationIDs(LifecycleCommand) (LifecycleMutationIDs, error)
}

// LifecycleDependencies contains explicit lifecycle service ports.
type LifecycleDependencies struct {
	Transactions     LifecycleTransactions
	CommittedResults CommittedLifecycleResultResolver
	MutationIDs      LifecycleMutationIDGenerator
	Clock            Clock
	Retry            RetryWaiter
}

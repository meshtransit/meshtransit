package authority

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/network"
)

// RebindImpactReader computes a freshly authorized deterministic preview.
type RebindImpactReader interface {
	PreviewRebind(context.Context, RebindPreview) (RebindImpact, error)
}

// RebindTransactions starts exact-scope target-replacement units of work.
type RebindTransactions interface {
	BeginRebind(context.Context, network.Scope) (RebindTransaction, error)
}

// RebindTransaction is one short target-replacement mutation unit.
type RebindTransaction interface {
	// DecisionTime is the database clock's time for this transaction: every
	// evaluation and persisted time of the attempt uses it.
	DecisionTime() time.Time
	Resolve(context.Context, RebindCommand, RebindMutationIDs, time.Time, time.Time) (RebindResolution, error)
	Apply(context.Context, RebindChange) (RebindResult, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// CommittedRebindResultResolver resolves uncertain commits by idempotency identity.
type CommittedRebindResultResolver interface {
	ResolveCommittedRebind(context.Context, RebindCommand, RebindMutationIDs) (RebindResult, bool, error)
}

// RebindMutationIDGenerator allocates stable IDs once for all attempts.
type RebindMutationIDGenerator interface {
	NewRebindMutationIDs(RebindCommand) (RebindMutationIDs, error)
}

// RebindDependencies contains all explicit rebinding service ports.
type RebindDependencies struct {
	Impacts          RebindImpactReader
	Transactions     RebindTransactions
	CommittedResults CommittedRebindResultResolver
	MutationIDs      RebindMutationIDGenerator
	Retry            RetryWaiter
}

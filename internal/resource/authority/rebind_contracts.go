package authority

import (
	"context"
	"time"

	"github.com/meshtransit/meshtransit/internal/network"
)

// RebindImpactReader computes a freshly authorized deterministic preview.
type RebindImpactReader interface {
	PreviewRebind(context.Context, RebindPreview, time.Time) (RebindImpact, error)
}

// RebindTransactions starts exact-scope target-replacement units of work.
type RebindTransactions interface {
	BeginRebind(context.Context, network.Scope) (RebindTransaction, error)
}

// RebindTransaction is one short target-replacement mutation unit.
type RebindTransaction interface {
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
	Clock            Clock
	Retry            RetryWaiter
}

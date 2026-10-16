package authority

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/network"
)

// GroupReplaceImpactReader computes a freshly authorized deterministic preview.
type GroupReplaceImpactReader interface {
	PreviewGroupReplace(context.Context, GroupReplacePreview) (GroupReplaceImpact, error)
}

// GroupReplaceTransactions starts exact-scope definition-replacement units of work.
type GroupReplaceTransactions interface {
	BeginGroupReplace(context.Context, network.Scope) (GroupReplaceTransaction, error)
}

// GroupReplaceTransaction is one short immutable-definition replacement unit.
type GroupReplaceTransaction interface {
	// DecisionTime is the database clock's time for this transaction: every
	// evaluation and persisted time of the attempt uses it.
	DecisionTime() time.Time
	Resolve(context.Context, GroupReplaceCommand, GroupReplaceMutationIDs, time.Time, time.Time) (GroupReplaceResolution, error)
	Apply(context.Context, GroupReplaceChange) (GroupReplaceResult, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// CommittedGroupReplaceResultResolver resolves uncertain commits by idempotency identity.
type CommittedGroupReplaceResultResolver interface {
	ResolveCommittedGroupReplace(context.Context, GroupReplaceCommand, GroupReplaceMutationIDs) (GroupReplaceResult, bool, error)
}

// GroupReplaceMutationIDGenerator allocates stable IDs once for all attempts.
type GroupReplaceMutationIDGenerator interface {
	NewGroupReplaceMutationIDs(GroupReplaceCommand) (GroupReplaceMutationIDs, error)
}

// GroupReplaceDependencies contains explicit definition-replacement service ports.
type GroupReplaceDependencies struct {
	Impacts          GroupReplaceImpactReader
	Transactions     GroupReplaceTransactions
	CommittedResults CommittedGroupReplaceResultResolver
	MutationIDs      GroupReplaceMutationIDGenerator
	Retry            RetryWaiter
}

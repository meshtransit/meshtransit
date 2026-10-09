package authority

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/network"
)

// ChangeImpactReader computes freshly authorized deterministic impact.
type ChangeImpactReader interface {
	PreviewAuthorityChange(context.Context, ChangePreview, time.Time) (ChangeImpact, error)
}

// ChangeRequestTransactions starts exact-scope proposal units of work.
type ChangeRequestTransactions interface {
	BeginAuthorityChangeRequest(context.Context, network.Scope) (ChangeRequestTransaction, error)
}

// ChangeRequestTransaction persists one pending two-person proposal.
type ChangeRequestTransaction interface {
	Resolve(context.Context, ChangeRequestCommand, ChangeRequestMutationIDs, time.Time, time.Time) (ChangeRequestResolution, error)
	Apply(context.Context, ChangeRequestChange) (ChangeRequestResult, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// CommittedAuthorityChangeRequestResolver resolves uncertain proposal commits.
type CommittedAuthorityChangeRequestResolver interface {
	ResolveCommittedAuthorityChangeRequest(context.Context, ChangeRequestCommand, ChangeRequestMutationIDs) (ChangeRequestResult, bool, error)
}

// ChangeConfirmationTransactions starts exact-scope confirmation units.
type ChangeConfirmationTransactions interface {
	BeginAuthorityChangeConfirmation(context.Context, network.Scope) (ChangeConfirmationTransaction, error)
}

// ChangeConfirmationTransaction applies one confirmed pending request.
type ChangeConfirmationTransaction interface {
	Resolve(context.Context, ChangeConfirmationCommand, ChangeConfirmationMutationIDs, time.Time, time.Time) (ChangeConfirmationResolution, error)
	Apply(context.Context, ChangeConfirmationChange) (ChangeConfirmationResult, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// CommittedAuthorityChangeConfirmationResolver resolves uncertain final commits.
type CommittedAuthorityChangeConfirmationResolver interface {
	ResolveCommittedAuthorityChangeConfirmation(context.Context, ChangeConfirmationCommand, ChangeConfirmationMutationIDs) (ChangeConfirmationResult, bool, error)
}

// ChangeMutationIDGenerator allocates stable IDs once per operation.
type ChangeMutationIDGenerator interface {
	NewAuthorityChangeRequestMutationIDs(ChangeRequestCommand) (ChangeRequestMutationIDs, error)
	NewAuthorityChangeConfirmationMutationIDs(ChangeConfirmationCommand) (ChangeConfirmationMutationIDs, error)
}

// ChangeDependencies contains explicit protected-workflow service ports.
type ChangeDependencies struct {
	Impacts                  ChangeImpactReader
	RequestTransactions      ChangeRequestTransactions
	CommittedRequests        CommittedAuthorityChangeRequestResolver
	ConfirmationTransactions ChangeConfirmationTransactions
	CommittedConfirmations   CommittedAuthorityChangeConfirmationResolver
	MutationIDs              ChangeMutationIDGenerator
	Clock                    Clock
	Retry                    RetryWaiter
}

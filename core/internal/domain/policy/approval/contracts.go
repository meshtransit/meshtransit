package approval

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy/compilation"
)

// Simulator produces compiler-identical, freshly authorized policy impact.
type Simulator interface {
	Simulate(
		context.Context,
		accountsession.Session,
		compilation.Request,
	) (simulation.Result, error)
}

// RequestTransactions starts exact-scope proposal units of work.
type RequestTransactions interface {
	BeginApprovalRequest(context.Context, network.Scope) (RequestTransaction, error)
}

// RequestTransaction persists one pending two-person approval request.
type RequestTransaction interface {
	// DecisionTime is the database clock's time for this transaction: every
	// evaluation and persisted time of the attempt uses it.
	DecisionTime() time.Time
	Resolve(
		context.Context,
		RequestCommand,
		RequestMutationIDs,
		time.Time,
		time.Time,
	) (RequestResolution, error)
	Apply(context.Context, RequestChange) (RequestResult, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// CommittedRequestResolver resolves uncertain proposal commits.
type CommittedRequestResolver interface {
	ResolveCommittedApprovalRequest(
		context.Context,
		RequestCommand,
		RequestMutationIDs,
	) (RequestResult, bool, error)
}

// Transactions starts exact-scope independent-decision units of work.
type Transactions interface {
	BeginPolicyApproval(context.Context, network.Scope) (Transaction, error)
}

// Transaction commits one immutable human approval decision.
type Transaction interface {
	// DecisionTime is the database clock's time for this transaction: every
	// evaluation and persisted time of the attempt uses it.
	DecisionTime() time.Time
	Resolve(
		context.Context,
		Command,
		MutationIDs,
		time.Time,
		time.Time,
	) (Resolution, error)
	Apply(context.Context, Change) (Result, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// CommittedApprovalResolver resolves uncertain independent-decision commits.
type CommittedApprovalResolver interface {
	ResolveCommittedPolicyApproval(
		context.Context,
		Command,
		MutationIDs,
	) (Result, bool, error)
}

// MutationIDGenerator allocates stable IDs once per operation.
type MutationIDGenerator interface {
	NewApprovalRequestMutationIDs(RequestCommand) (RequestMutationIDs, error)
	NewPolicyApprovalMutationIDs(Command) (MutationIDs, error)
}

// RetryWaiter applies bounded delay between complete transaction attempts.
type RetryWaiter interface {
	Wait(context.Context, int) error
}

// Dependencies contains every explicit policy approval service port.
type Dependencies struct {
	Simulator            Simulator
	RequestTransactions  RequestTransactions
	CommittedRequests    CommittedRequestResolver
	ApprovalTransactions Transactions
	CommittedApprovals   CommittedApprovalResolver
	MutationIDs          MutationIDGenerator
	Retry                RetryWaiter
}

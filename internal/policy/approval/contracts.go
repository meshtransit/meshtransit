package approval

import (
	"context"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/policy/compilation"
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

// Clock supplies stable decision time across complete transaction retries.
type Clock interface{ Now() time.Time }

// SystemClock uses the process wall clock.
type SystemClock struct{}

// Now returns current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }

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
	Clock                Clock
	Retry                RetryWaiter
}

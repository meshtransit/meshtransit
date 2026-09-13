// Package registration implements the enrollment registration application use case.
package registration

import (
	"context"
	"time"

	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
)

// Transactions starts explicit registration units of work and resolves an
// uncertain commit against authoritative storage.
type Transactions interface {
	Begin(context.Context, network.Scope) (Transaction, error)
	ResolveCommitted(context.Context, Command) (Result, bool, error)
}

// Transaction is one short registration unit of work. Resolve acquires locks
// in global order; Apply writes the complete atomic change. The application
// service, never the adapter, decides whether to commit or roll back.
type Transaction interface {
	Resolve(context.Context, Command) (Resolution, error)
	Apply(context.Context, Change) (Result, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// NodeIDGenerator creates application-owned public Node identifiers.
type NodeIDGenerator interface {
	NewNodeID() (node.ID, error)
}

// Clock supplies one stable decision time for every replayable attempt.
type Clock interface {
	Now() time.Time
}

// RetryWaiter applies bounded backoff between complete transaction attempts.
type RetryWaiter interface {
	Wait(context.Context, int) error
}

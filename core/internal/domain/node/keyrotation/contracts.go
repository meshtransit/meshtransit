// Package keyrotation owns authenticated WireGuard Node-key epoch rotation.
package keyrotation

import (
	"context"
	"time"
)

// Transactions starts short, explicit Node-key rotation units of work.
type Transactions interface {
	Begin(context.Context, Command) (Transaction, error)
}

// Transaction locks current identity authority and atomically applies one rotation.
type Transaction interface {
	// DecisionTime is the database clock's time for this transaction: every
	// evaluation and persisted time of the attempt uses it.
	DecisionTime() time.Time
	Resolve(context.Context, Command) (Resolution, error)
	Apply(context.Context, Change) (Result, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// MutationIDGenerator creates stable public IDs once for all retry attempts.
type MutationIDGenerator interface {
	NewMutationIDs() (MutationIDs, error)
}

// RetryWaiter applies bounded delay between complete transaction attempts.
type RetryWaiter interface {
	Wait(context.Context, int) error
}

// Dependencies contains every explicit port required by Service.
type Dependencies struct {
	Transactions Transactions
	MutationIDs  MutationIDGenerator
	Retry        RetryWaiter
}

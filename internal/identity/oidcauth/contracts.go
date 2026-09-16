package oidcauth

import "context"

// Transactions starts explicit short AuthTransaction creation units of work.
type Transactions interface {
	Begin(context.Context, Route) (Transaction, error)
}

// Transaction is one creation unit with application-owned completion.
type Transaction interface {
	Create(context.Context, Pending) (Created, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// CommittedCreationResolver resolves an uncertain commit without creating a second row.
type CommittedCreationResolver interface {
	ResolveCommitted(context.Context, Pending) (Created, bool, error)
}

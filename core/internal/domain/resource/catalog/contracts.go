package catalog

import (
	"context"

	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/resource"
)

// Transactions starts exact-scope Resource catalog units of work.
type Transactions interface {
	Begin(context.Context, network.Scope) (Transaction, error)
}

// Transaction is one freshly authorized Resource catalog read unit.
type Transaction interface {
	// Authorize admits the session for a permission at the database clock's
	// time for this transaction.
	Authorize(context.Context, accountsession.Session, authorization.Permission) error
	Revisions(context.Context) (inventory int64, group int64, err error)
	Resource(context.Context, resource.ID) (Resource, error)
	Resources(context.Context, resource.State, publicid.ID, int) ([]Resource, error)
	Group(context.Context, resource.GroupID) (Group, error)
	Groups(context.Context, resource.State, publicid.ID, int) ([]Group, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// Dependencies contains every port required by Service.
type Dependencies struct {
	Transactions Transactions
}

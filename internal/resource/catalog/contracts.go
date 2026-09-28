package catalog

import (
	"context"
	"time"

	"github.com/meshtransit/meshtransit/internal/authorization"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
)

// Transactions starts exact-scope Resource catalog units of work.
type Transactions interface {
	Begin(context.Context, network.Scope) (Transaction, error)
}

// Transaction is one freshly authorized Resource catalog read unit.
type Transaction interface {
	Authorize(context.Context, accountsession.Session, authorization.Permission, time.Time) error
	Revisions(context.Context) (inventory int64, group int64, err error)
	Resource(context.Context, resource.ID) (Resource, error)
	Resources(context.Context, resource.State, publicid.ID, int) ([]Resource, error)
	Group(context.Context, resource.GroupID) (Group, error)
	Groups(context.Context, resource.State, publicid.ID, int) ([]Group, error)
	Commit(context.Context) error
	Rollback(context.Context) error
}

// Clock supplies the authorization evaluation time.
type Clock interface{ Now() time.Time }

// Dependencies contains every port required by Service.
type Dependencies struct {
	Transactions Transactions
	Clock        Clock
}

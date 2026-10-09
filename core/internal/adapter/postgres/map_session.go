package postgres

import (
	"errors"
	"time"

	postgresmapsession "github.com/meshtransit/meshtransit/core/internal/adapter/postgres/mapsession"
)

// ErrInvalidMapSessionStore reports a pool without runtime read authority.
var ErrInvalidMapSessionStore = errors.New("invalid postgres map session store")

// MapSessionOptions bounds one authoritative snapshot read.
type MapSessionOptions = postgresmapsession.Options

var _ postgresmapsession.Observer = (*postgresPoolMetrics)(nil)

// NewMapSessionStore constructs an exact-scope snapshot reader from a runtime pool.
func NewMapSessionStore(
	pool *Pool,
	options MapSessionOptions,
) (*postgresmapsession.Store, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.mapSessionStore == nil {
		return nil, ErrInvalidMapSessionStore
	}
	return pool.mapSessionStore(options)
}

// ObserveMapSession records a bounded low-cardinality PostgreSQL outcome.
func (metrics *postgresPoolMetrics) ObserveMapSession(
	operation postgresmapsession.Operation,
	duration time.Duration,
	err error,
) {
	switch operation {
	case postgresmapsession.OperationLoad:
		metrics.observeOperation(postgresOperationMapSessionSnapshot, duration, err)
	case postgresmapsession.OperationObserveClientVersion:
		metrics.observeOperation(postgresOperationMapSessionClientVersion, duration, err)
	case postgresmapsession.OperationUnknown:
		return
	}
}

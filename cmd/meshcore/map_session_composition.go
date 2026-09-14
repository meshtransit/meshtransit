package main

import (
	"errors"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/control/mapsession"
)

var errInvalidMapSessionComposition = errors.New("invalid map session composition")

func composeMapSession(
	mapConfig config.ControlMapConfig,
	runtimePool *postgresadapter.Pool,
) (*mapsession.Service, error) {
	if runtimePool == nil {
		return nil, errInvalidMapSessionComposition
	}
	store, err := postgresadapter.NewMapSessionStore(
		runtimePool,
		postgresadapter.MapSessionOptions{
			StatementTimeout: mapConfig.StatementTimeout,
			IdleTimeout:      mapConfig.TransactionIdleLimit,
		},
	)
	if err != nil {
		return nil, errors.Join(errInvalidMapSessionComposition, err)
	}
	return newMapSessionService(store)
}

func newMapSessionService(store mapsession.SnapshotStore) (*mapsession.Service, error) {
	if store == nil {
		return nil, errInvalidMapSessionComposition
	}
	service, err := mapsession.NewService(store)
	if err != nil {
		return nil, errors.Join(errInvalidMapSessionComposition, err)
	}
	return service, nil
}

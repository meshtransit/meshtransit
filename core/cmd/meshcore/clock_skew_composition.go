package main

import (
	"errors"
	"log/slog"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/core/internal/platform/clockskew"
)

var errInvalidClockSkewComposition = errors.New("invalid clock skew observer composition")

// composeClockSkewObserver samples the database clock through whichever pool
// this role owns. Observation is diagnostic only and never gates readiness.
func composeClockSkewObserver(pools postgresPools, logger *slog.Logger) (*clockskew.Observer, error) {
	pool := pools.runtime
	if pool == nil {
		pool = pools.worker
	}
	if pool == nil || logger == nil {
		return nil, errInvalidClockSkewComposition
	}
	observer, err := clockskew.New(clockskew.DefaultOptions(), pool, logger)
	if err != nil {
		return nil, errors.Join(errInvalidClockSkewComposition, err)
	}
	return observer, nil
}

var (
	_ app.Service       = (*clockskew.Observer)(nil)
	_ clockskew.Sampler = (*postgresadapter.Pool)(nil)
)

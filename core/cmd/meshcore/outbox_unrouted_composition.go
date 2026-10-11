package main

import (
	"errors"
	"log/slog"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/outbox/unrouted"
	"meshtransit.net/core/internal/platform/app"
)

var errInvalidOutboxUnroutedComposition = errors.New("invalid unrouted outbox retirer composition")

// outboxUnroutedWorkerID labels the rows the retirer closes (claimed_by).
const outboxUnroutedWorkerID = "outbox-unrouted"

func composeOutboxUnroutedRetirer(pool *postgresadapter.Pool, logger *slog.Logger) (*unrouted.Retirer, error) {
	if pool == nil || logger == nil {
		return nil, errInvalidOutboxUnroutedComposition
	}
	store, err := postgresadapter.NewOutboxStore(pool)
	if err != nil {
		return nil, errors.Join(errInvalidOutboxUnroutedComposition, err)
	}
	retirer, err := unrouted.New(unrouted.DefaultOptions(outboxUnroutedWorkerID), store, logger)
	if err != nil {
		return nil, errors.Join(errInvalidOutboxUnroutedComposition, err)
	}
	return retirer, nil
}

var _ app.Service = (*unrouted.Retirer)(nil)

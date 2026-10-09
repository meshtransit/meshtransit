package main

import (
	"errors"
	"log/slog"

	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/audit/partitions"
	"github.com/meshtransit/meshtransit/core/internal/platform/app"
)

var errInvalidAuditPartitionComposition = errors.New("invalid audit partition maintainer composition")

func composeAuditPartitionMaintainer(pool *postgresadapter.Pool, logger *slog.Logger) (*partitions.Maintainer, error) {
	if pool == nil || logger == nil {
		return nil, errInvalidAuditPartitionComposition
	}
	store, err := postgresadapter.NewAuditPartitionStore(pool)
	if err != nil {
		return nil, errors.Join(errInvalidAuditPartitionComposition, err)
	}
	maintainer, err := partitions.New(partitions.DefaultOptions(), store, logger)
	if err != nil {
		return nil, errors.Join(errInvalidAuditPartitionComposition, err)
	}
	return maintainer, nil
}

var _ app.Service = (*partitions.Maintainer)(nil)

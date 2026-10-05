package mapsession

import (
	"context"
	"errors"
	"fmt"

	appmapsession "github.com/meshtransit/meshtransit/internal/control/mapsession"
)

const loadDirectEdgesSQL = `SELECT edge::TEXT
FROM mesh_ops.load_direct_share_map_edges_v1($1::BYTEA, $2::BYTEA, $3::INTEGER) AS edge`

const loadAliasEdgesSQL = `SELECT edge::TEXT
FROM mesh_ops.load_device_alias_map_edges_v3($1::BYTEA, $2::BYTEA, $3::INTEGER) AS edge`

func (store *Store) loadDirectEdges(
	ctx context.Context, transaction databaseTransaction, self appmapsession.Snapshot,
	machineFingerprint, nodeKey []byte,
) (appmapsession.Snapshot, error) {
	if store.options.EnableDeviceAliases {
		var err error
		self, err = loadSharingDependencies(ctx, transaction, self, machineFingerprint, nodeKey)
		if err != nil {
			return appmapsession.Snapshot{}, err
		}
	}
	projections, err := readSharingEdges(ctx, transaction, self, machineFingerprint, nodeKey, loadDirectEdgesSQL, decodeDirectEdge)
	if err != nil {
		return appmapsession.Snapshot{}, err
	}
	if store.options.EnableDeviceAliases {
		aliases, err := readSharingEdges(ctx, transaction, self, machineFingerprint, nodeKey, loadAliasEdgesSQL, decodeAliasEdge)
		if err != nil {
			return appmapsession.Snapshot{}, err
		}
		projections = append(projections, aliases...)
	}
	if len(projections) == 0 {
		return self, nil
	}
	result, err := self.WithDirectDeviceProjections(projections)
	if err != nil {
		return appmapsession.Snapshot{}, errors.Join(ErrSnapshotEvidence, err)
	}
	return result, nil
}

func readSharingEdges(
	ctx context.Context, transaction databaseTransaction, self appmapsession.Snapshot,
	machineFingerprint, nodeKey []byte, query string,
	decode func([]byte, appmapsession.Snapshot) (appmapsession.DirectDeviceProjection, error),
) ([]appmapsession.DirectDeviceProjection, error) {
	rows, err := transaction.Query(ctx, query, machineFingerprint, nodeKey,
		appmapsession.MaximumDirectDeviceProjections+1)
	if err != nil || rows == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read direct sharing edges: %w", err))
	}
	defer rows.Close()
	projections := make([]appmapsession.DirectDeviceProjection, 0, 4)
	for rows.Next() {
		if len(projections) == appmapsession.MaximumDirectDeviceProjections {
			return nil, errors.Join(ErrLoadSnapshot, ErrSnapshotEvidence)
		}
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan direct sharing edge: %w", err))
		}
		projection, err := decode([]byte(encoded), self)
		if err != nil {
			return nil, err
		}
		projections = append(projections, projection)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate direct sharing edges: %w", err))
	}
	return projections, nil
}

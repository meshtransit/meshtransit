package mapsession

import (
	"context"
	"errors"
	"fmt"

	appmapsession "github.com/meshtransit/meshtransit/core/internal/control/mapsession"
)

const loadDirectEdgesSQL = `SELECT edge::TEXT
FROM mesh_ops.load_direct_share_map_edges_v1($1::BYTEA, $2::BYTEA, $3::INTEGER) AS edge`

const loadAliasEdgesSQL = `SELECT edge::TEXT
FROM mesh_ops.load_device_alias_map_edges_v3($1::BYTEA, $2::BYTEA, $3::INTEGER) AS edge`

// loadReachableAliasEdgesSQL counts only shares this Device may reach
// (schema 114). It is used once the operator granted it to this role.
const loadReachableAliasEdgesSQL = `SELECT edge::TEXT
FROM mesh_ops.load_device_alias_map_edges_v4($1::BYTEA, $2::BYTEA, $3::INTEGER) AS edge`

const reachableAliasEdgesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_device_alias_map_edges_v4(bytea,bytea,integer)'), 'EXECUTE'), FALSE)`

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
		query, err := aliasEdgesQuery(ctx, transaction)
		if err != nil {
			return appmapsession.Snapshot{}, err
		}
		aliases, err := readSharingEdges(ctx, transaction, self, machineFingerprint, nodeKey, query, decodeAliasEdge)
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

// aliasEdgesQuery selects the reachable-share reader once runtime may execute
// it, so a rolling upgrade or a pending operator step keeps the previous one.
func aliasEdgesQuery(ctx context.Context, transaction databaseTransaction) (string, error) {
	rows, err := transaction.Query(ctx, reachableAliasEdgesGrantedSQL)
	if err != nil || rows == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return "", errors.Join(ErrLoadSnapshot, fmt.Errorf("check alias map reader: %w", err))
	}
	defer rows.Close()
	granted := false
	if rows.Next() {
		if err := rows.Scan(&granted); err != nil {
			return "", errors.Join(ErrLoadSnapshot, fmt.Errorf("scan alias map reader: %w", err))
		}
	}
	if err := rows.Err(); err != nil {
		return "", errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate alias map reader: %w", err))
	}
	if granted {
		return loadReachableAliasEdgesSQL, nil
	}
	return loadAliasEdgesSQL, nil
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

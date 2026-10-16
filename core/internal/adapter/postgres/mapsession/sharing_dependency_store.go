package mapsession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
)

const loadSharingDependenciesSQL = `SELECT dependency::TEXT
FROM mesh_ops.load_device_sharing_dependencies_v1($1::BYTEA,$2::BYTEA,$3::INTEGER) AS dependency`

// loadBoundSharingDependenciesSQL gives a consumer Device a dependency only
// while it is the source of a rule to the share (schema 146), so the rest of
// a consumer Network keeps the shared map view. It is used once the operator
// granted it to this role.
const loadBoundSharingDependenciesSQL = `SELECT dependency::TEXT
FROM mesh_ops.load_device_sharing_dependencies_v2($1::BYTEA,$2::BYTEA,$3::INTEGER) AS dependency`

const boundSharingDependenciesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_device_sharing_dependencies_v2(bytea,bytea,integer)'), 'EXECUTE'), FALSE)`

// loadScaledSharingDependenciesSQL is v2 bounded by the map peer limit
// instead of 256 contracts (schema 147), used once the operator granted it.
const loadScaledSharingDependenciesSQL = `SELECT dependency::TEXT
FROM mesh_ops.load_device_sharing_dependencies_v3($1::BYTEA,$2::BYTEA,$3::INTEGER) AS dependency`

const scaledSharingDependenciesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_device_sharing_dependencies_v3(bytea,bytea,integer)'), 'EXECUTE'), FALSE)`

// loadSelectiveSharingDependenciesSQL is v3 choosing contracts from this
// Device's rules and targets instead of every contract of its Network
// (schema 149), used once the operator granted it.
const loadSelectiveSharingDependenciesSQL = `SELECT dependency::TEXT
FROM mesh_ops.load_device_sharing_dependencies_v4($1::BYTEA,$2::BYTEA,$3::INTEGER) AS dependency`

const selectiveSharingDependenciesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_device_sharing_dependencies_v4(bytea,bytea,integer)'), 'EXECUTE'), FALSE)`

// loadKeyedSharingDependenciesSQL is v4 authenticating the Device by its node
// key instead of scanning its Network (schema 155), used once the operator
// granted it.
const loadKeyedSharingDependenciesSQL = `SELECT dependency::TEXT
FROM mesh_ops.load_device_sharing_dependencies_v5($1::BYTEA,$2::BYTEA,$3::INTEGER) AS dependency`

const keyedSharingDependenciesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_device_sharing_dependencies_v5(bytea,bytea,integer)'), 'EXECUTE'), FALSE)`

// loadNetworkOnceSharingDependenciesSQL is v5 proving each remote Network
// once instead of every contract (schema 156), used once the operator
// granted it.
const loadNetworkOnceSharingDependenciesSQL = `SELECT dependency::TEXT
FROM mesh_ops.load_device_sharing_dependencies_v6($1::BYTEA,$2::BYTEA,$3::INTEGER) AS dependency`

const networkOnceSharingDependenciesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_device_sharing_dependencies_v6(bytea,bytea,integer)'), 'EXECUTE'), FALSE)`

func (store *Store) loadSharingDependencies(ctx context.Context, transaction databaseTransaction, self appmapsession.Snapshot, machineFingerprint, nodeKey []byte) (appmapsession.Snapshot, error) {
	reader, err := sharingDependenciesReader(ctx, transaction)
	if err != nil {
		return appmapsession.Snapshot{}, err
	}
	store.observeReader(ctx, FunctionPathSharingDependencies, reader)
	requested := reader.limit + 1 // one more row reveals a legacy overflow
	if reader.scaled {
		requested = reader.limit
	}
	rows, err := transaction.Query(ctx, reader.query, machineFingerprint, nodeKey, requested)
	if err != nil || rows == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return appmapsession.Snapshot{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("read sharing dependencies: %w", err))
	}
	defer rows.Close()
	scopes := make([]network.Scope, 0, 4)
	limited := false
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return appmapsession.Snapshot{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan sharing dependency: %w", err))
		}
		if reader.scaled && encoded == limitedEdge {
			limited = true
			continue
		}
		if len(scopes) == reader.limit || limited {
			return appmapsession.Snapshot{}, ErrSnapshotEvidence
		}
		var record struct {
			WorkspaceID string `json:"workspace_id"`
			NetworkID   string `json:"network_id"`
		}
		if err := json.Unmarshal([]byte(encoded), &record); err != nil {
			return appmapsession.Snapshot{}, errors.Join(ErrSnapshotEvidence, err)
		}
		scope, err := scopeFromText(record.WorkspaceID, record.NetworkID)
		if err != nil {
			return appmapsession.Snapshot{}, err
		}
		scopes = append(scopes, scope)
	}
	if err := rows.Err(); err != nil {
		return appmapsession.Snapshot{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate sharing dependencies: %w", err))
	}
	result, err := self.WithSharingDependencies(scopes)
	if err != nil {
		return appmapsession.Snapshot{}, errors.Join(ErrSnapshotEvidence, err)
	}
	if limited {
		// Contracts past the limit wake no refresh; report the map limited.
		if result, err = result.WithOmittedShares(1); err != nil {
			return appmapsession.Snapshot{}, errors.Join(ErrSnapshotEvidence, err)
		}
	}
	return result, nil
}

// sharingDependenciesReader selects the newest dependency reader runtime may
// execute, so a rolling upgrade or a pending operator step keeps the
// previous one.
func sharingDependenciesReader(ctx context.Context, transaction databaseTransaction) (edgeReader, error) {
	once, err := functionGranted(ctx, transaction, networkOnceSharingDependenciesGrantedSQL)
	if err != nil {
		return edgeReader{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("check sharing dependency reader: %w", err))
	}
	if once {
		return edgeReader{query: loadNetworkOnceSharingDependenciesSQL, limit: appmapsession.MaximumDirectDeviceProjections,
			scaled: true}, nil
	}
	keyed, err := functionGranted(ctx, transaction, keyedSharingDependenciesGrantedSQL)
	if err != nil {
		return edgeReader{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("check sharing dependency reader: %w", err))
	}
	if keyed {
		return edgeReader{query: loadKeyedSharingDependenciesSQL, limit: appmapsession.MaximumDirectDeviceProjections,
			scaled: true}, nil
	}
	selective, err := functionGranted(ctx, transaction, selectiveSharingDependenciesGrantedSQL)
	if err != nil {
		return edgeReader{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("check sharing dependency reader: %w", err))
	}
	if selective {
		return edgeReader{query: loadSelectiveSharingDependenciesSQL, limit: appmapsession.MaximumDirectDeviceProjections,
			scaled: true}, nil
	}
	scaled, err := functionGranted(ctx, transaction, scaledSharingDependenciesGrantedSQL)
	if err != nil {
		return edgeReader{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("check sharing dependency reader: %w", err))
	}
	if scaled {
		return edgeReader{query: loadScaledSharingDependenciesSQL, limit: appmapsession.MaximumDirectDeviceProjections,
			scaled: true}, nil
	}
	granted, err := functionGranted(ctx, transaction, boundSharingDependenciesGrantedSQL)
	if err != nil {
		return edgeReader{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("check sharing dependency reader: %w", err))
	}
	if granted {
		return edgeReader{query: loadBoundSharingDependenciesSQL, limit: legacyEdgeLimit}, nil
	}
	return edgeReader{query: loadSharingDependenciesSQL, limit: legacyEdgeLimit}, nil
}

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

func loadSharingDependencies(ctx context.Context, transaction databaseTransaction, self appmapsession.Snapshot, machineFingerprint, nodeKey []byte) (appmapsession.Snapshot, error) {
	query, err := sharingDependenciesQuery(ctx, transaction)
	if err != nil {
		return appmapsession.Snapshot{}, err
	}
	rows, err := transaction.Query(ctx, query, machineFingerprint, nodeKey, appmapsession.MaximumDirectDeviceProjections+1)
	if err != nil || rows == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return appmapsession.Snapshot{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("read sharing dependencies: %w", err))
	}
	defer rows.Close()
	scopes := make([]network.Scope, 0, 4)
	for rows.Next() {
		if len(scopes) == appmapsession.MaximumDirectDeviceProjections {
			return appmapsession.Snapshot{}, ErrSnapshotEvidence
		}
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return appmapsession.Snapshot{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan sharing dependency: %w", err))
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
	return result, nil
}

// sharingDependenciesQuery selects the narrowed reader once runtime may
// execute it, so a rolling upgrade or a pending operator step keeps v1.
func sharingDependenciesQuery(ctx context.Context, transaction databaseTransaction) (string, error) {
	granted, err := functionGranted(ctx, transaction, boundSharingDependenciesGrantedSQL)
	if err != nil {
		return "", errors.Join(ErrLoadSnapshot, fmt.Errorf("check sharing dependency reader: %w", err))
	}
	if granted {
		return loadBoundSharingDependenciesSQL, nil
	}
	return loadSharingDependenciesSQL, nil
}

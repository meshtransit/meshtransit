package mapsession

import (
	"context"
	"errors"
	"fmt"
	"strings"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
)

const (
	// selfIdentityGrantedSQL: this role may run both schema 287 readers.
	selfIdentityGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.read_map_self_identity_v1(bytea,bytea)'), 'EXECUTE'), FALSE)
  AND COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.read_scope_workspace_name_v1()'), 'EXECUTE'), FALSE)`
	// loadNetworkHeaderWithWorkspaceSQL is the header with the scope's
	// display codes (schema 169) and Workspace name (schema 287).
	loadNetworkHeaderWithWorkspaceSQL = `SELECT header.network_display_name, header.recovery_epoch,
    codes.workspace_code, codes.network_code, workspace.workspace_display_name
FROM mesh_ops.load_map_network_header_v1() AS header
LEFT JOIN mesh_ops.read_scope_workspace_name_v1() AS workspace ON TRUE
LEFT JOIN mesh_ops.read_scope_display_codes_v1() AS codes ON TRUE`
)

// loadSnapshotWithIdentitySQL is the snapshot read with, in the same
// statement, the session's own Device's account names (schema 287): the
// reader is bound to the installed scope and the same authenticated keys,
// and adds no round trip.
var loadSnapshotWithIdentitySQL = withSelfIdentityColumns(loadSnapshotSQL)

func withSelfIdentityColumns(query string) string {
	query = strings.Replace(query, "\nFROM mesh.device AS device\n",
		`,
    identity.workspace_display_name,
    identity.ownership,
    identity.owner_display_name
FROM mesh.device AS device
`, 1)
	return strings.Replace(query, "\nWHERE machine.fingerprint = $1::BYTEA\n",
		`
LEFT JOIN LATERAL mesh_ops.read_map_self_identity_v1($1::BYTEA, $2::BYTEA) AS identity ON TRUE
WHERE machine.fingerprint = $1::BYTEA
`, 1)
}

// readsSelfIdentity reports whether this role may run the schema 287
// readers; once granted it is not probed again.
func (store *Store) readsSelfIdentity(ctx context.Context, transaction databaseTransaction) (bool, error) {
	if store.selfIdentityGranted.Load() {
		return true, nil
	}
	granted, err := functionGranted(ctx, transaction, selfIdentityGrantedSQL)
	if err != nil {
		return false, errors.Join(ErrLoadSnapshot, fmt.Errorf("check self identity readers: %w", err))
	}
	if granted {
		store.selfIdentityGranted.Store(true)
	}
	return granted, nil
}

// SelfIdentityGranted reports, in a read of its own, whether this role may
// run schema 287's readers. Core offers self.identity1 only then.
func (store *Store) SelfIdentityGranted(ctx context.Context) (granted bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil {
		return false, ErrInvalidStore
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		return false, errors.Join(ErrLoadSnapshot, nonNil(err))
	}
	defer func() { resultErr = errors.Join(resultErr, rollback(transaction)) }()
	return functionGranted(ctx, transaction, selfIdentityGrantedSQL)
}

// snapshotSQL is the snapshot read this role may run: with the account
// names once schema 287 is granted.
func (store *Store) snapshotSQL(ctx context.Context, transaction databaseTransaction) (string, bool, error) {
	granted, err := store.readsSelfIdentity(ctx, transaction)
	if err != nil {
		return "", false, err
	}
	if granted {
		return loadSnapshotWithIdentitySQL, true, nil
	}
	return loadSnapshotSQL, false, nil
}

// selfIdentity validates the account names a read returned. They are
// presentation only: no row or names the map cannot carry give no
// identity, never a failed map.
func (store *Store) selfIdentity(workspaceName, ownershipValue, ownerName *string) appmapsession.SelfIdentity {
	if workspaceName == nil || ownershipValue == nil {
		return appmapsession.SelfIdentity{}
	}
	ownership, err := appmapsession.ParseOwnership(*ownershipValue)
	if err != nil {
		store.stats.selfIdentityRejected.Add(1)
		return appmapsession.SelfIdentity{}
	}
	owner := ""
	if ownerName != nil {
		owner = *ownerName
	}
	identity, err := appmapsession.NewSelfIdentity(*workspaceName, ownership, owner)
	if err != nil {
		store.stats.selfIdentityRejected.Add(1)
		return appmapsession.SelfIdentity{}
	}
	return identity
}

// networkHeaderSQL is the header query this role may run: with the
// Workspace's name once schema 287 is granted.
func (store *Store) networkHeaderSQL(ctx context.Context, transaction databaseTransaction) (string, bool, error) {
	granted, err := store.readsSelfIdentity(ctx, transaction)
	if err != nil {
		return "", false, err
	}
	if granted {
		return loadNetworkHeaderWithWorkspaceSQL, true, nil
	}
	return loadNetworkHeaderSQL, false, nil
}

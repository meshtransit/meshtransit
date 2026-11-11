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
	// selfIdentityEmailGrantedSQL: this role may run schema 288's reader,
	// which adds the owner's verified email.
	selfIdentityEmailGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.read_map_self_identity_v2(bytea,bytea)'), 'EXECUTE'), FALSE)`
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
var loadSnapshotWithIdentitySQL = withSelfIdentityColumns(loadSnapshotSQL, false)

// loadSnapshotWithIdentityEmailSQL adds the owner's verified email through
// schema 288's reader, bound like v1.
var loadSnapshotWithIdentityEmailSQL = withSelfIdentityColumns(loadSnapshotSQL, true)

func withSelfIdentityColumns(query string, email bool) string {
	columns, reader := `,
    identity.workspace_display_name,
    identity.ownership,
    identity.owner_display_name
FROM mesh.device AS device
`, "read_map_self_identity_v1"
	if email {
		columns, reader = `,
    identity.workspace_display_name,
    identity.ownership,
    identity.owner_display_name,
    identity.owner_email
FROM mesh.device AS device
`, "read_map_self_identity_v2"
	}
	query = strings.Replace(query, "\nFROM mesh.device AS device\n", columns, 1)
	return strings.Replace(query, "\nWHERE machine.fingerprint = $1::BYTEA\n",
		`
LEFT JOIN LATERAL mesh_ops.`+reader+`($1::BYTEA, $2::BYTEA) AS identity ON TRUE
WHERE machine.fingerprint = $1::BYTEA
`, 1)
}

// identityReaders is what this role may read of a Device's account.
type identityReaders int32

const (
	identityReadersNone  identityReaders = iota // before schema 287
	identityReadersNames                        // schema 287: the names
	identityReadersEmail                        // schema 288: the names and the owner's email
)

// readsSelfIdentity reports which account readers this role may run. Once
// any is granted it is not probed again: migrations run before Core starts,
// so a Core started on schema 287 reads names without the email until it
// restarts.
func (store *Store) readsSelfIdentity(ctx context.Context, transaction databaseTransaction) (identityReaders, error) {
	if readers := identityReaders(store.selfIdentityReaders.Load()); readers != identityReadersNone {
		return readers, nil
	}
	names, err := functionGranted(ctx, transaction, selfIdentityGrantedSQL)
	if err != nil {
		return identityReadersNone, errors.Join(ErrLoadSnapshot, fmt.Errorf("check self identity readers: %w", err))
	}
	if !names {
		return identityReadersNone, nil
	}
	email, err := functionGranted(ctx, transaction, selfIdentityEmailGrantedSQL)
	if err != nil {
		// The names still go out; the next read probes the email again. A
		// database-side failure aborts this transaction anyway, so this
		// helps only errors raised before the database answers.
		return identityReadersNames, nil
	}
	readers := identityReadersNames
	if email {
		readers = identityReadersEmail
	}
	store.selfIdentityReaders.Store(int32(readers))
	return readers, nil
}

// SelfIdentityGranted reports, in a read of its own, whether this role may
// run schema 287's readers. Core offers self.identity1 only then; schema
// 288's reader only adds the email, so its absence costs no names.
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

// SelfIdentityEmailGranted reports, in a read of its own, whether this role
// may run schema 288's reader.
func (store *Store) SelfIdentityEmailGranted(ctx context.Context) (granted bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil {
		return false, ErrInvalidStore
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		return false, errors.Join(ErrLoadSnapshot, nonNil(err))
	}
	defer func() { resultErr = errors.Join(resultErr, rollback(transaction)) }()
	return functionGranted(ctx, transaction, selfIdentityEmailGrantedSQL)
}

// snapshotSQL is the snapshot read this role may run: with the account
// names once schema 287 is granted, and the owner's email once 288 is.
func (store *Store) snapshotSQL(ctx context.Context, transaction databaseTransaction) (string, identityReaders, error) {
	readers, err := store.readsSelfIdentity(ctx, transaction)
	if err != nil {
		return "", identityReadersNone, err
	}
	switch readers {
	case identityReadersEmail:
		return loadSnapshotWithIdentityEmailSQL, readers, nil
	case identityReadersNames:
		return loadSnapshotWithIdentitySQL, readers, nil
	default:
		return loadSnapshotSQL, identityReadersNone, nil
	}
}

// selfIdentity validates the account names a read returned. They are
// presentation only: no row or names the map cannot carry give no
// identity, never a failed map.
func (store *Store) selfIdentity(workspaceName, ownershipValue, ownerName *string,
	readers identityReaders, ownerEmail *string,
) appmapsession.SelfIdentity {
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
	if readers != identityReadersEmail {
		return identity
	}
	email := ""
	if ownerEmail != nil {
		email = *ownerEmail
	}
	identity = identity.WithOwnerEmail(email)
	if shown, _ := identity.OwnerEmail(); ownership == appmapsession.OwnershipMember && email != "" &&
		shown != email {
		// Only the email is dropped; the names stay. A Workspace's Device
		// never carries one (the reader gives none).
		store.stats.selfIdentityEmailRejected.Add(1)
	}
	return identity
}

// networkHeaderSQL is the header query this role may run: with the
// Workspace's name once schema 287 is granted.
func (store *Store) networkHeaderSQL(ctx context.Context, transaction databaseTransaction) (string, bool, error) {
	readers, err := store.readsSelfIdentity(ctx, transaction)
	if err != nil {
		return "", false, err
	}
	if readers != identityReadersNone {
		return loadNetworkHeaderWithWorkspaceSQL, true, nil
	}
	return loadNetworkHeaderSQL, false, nil
}

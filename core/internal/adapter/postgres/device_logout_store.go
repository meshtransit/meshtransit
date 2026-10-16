package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	resolveLogoutScopeSQL = `SELECT workspace_public_id::TEXT, network_public_id::TEXT
FROM mesh_ops.resolve_map_session_scope($1::BYTEA, $2::BYTEA)`
	logoutDeviceSQL = `SELECT mesh_ops.logout_device_v1($1::BYTEA,$2::BYTEA,$3::UUID,$4::TIMESTAMPTZ)::TEXT`
	// deviceLogoutPermission names the authority a node uses on itself.
	deviceLogoutPermission = "device.logout_self"
)

// DeviceLogoutStore revokes a Device at its node's request (MTCP Logout,
// schema 138) and records device.logged_out on the Network stream, with the
// Device's owner as the actor, in the same transaction.
type DeviceLogoutStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ control.DeviceLogoutStore = (*DeviceLogoutStore)(nil)

// NewDeviceLogoutStore uses the runtime pool.
func NewDeviceLogoutStore(pool *Pool, options AccountSessionOptions) (*DeviceLogoutStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, control.ErrInvalidDeviceLogoutService
	}
	return &DeviceLogoutStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

// LogoutDevice implements control.DeviceLogoutStore. The logout is evaluated
// and stamped on the database clock.
func (store *DeviceLogoutStore) LogoutDevice(ctx context.Context, identity control.AuthenticatedNode) (
	control.DeviceLogout, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return control.DeviceLogout{}, control.ErrInvalidDeviceLogoutService
	}
	changeID, err := publicid.New()
	if err != nil {
		return control.DeviceLogout{}, control.ErrDeviceLogoutUnavailable
	}
	fingerprint, nodeKey := identity.MachineFingerprint(), identity.NodeKey()
	var logout control.DeviceLogout
	err = store.transact(ctx, func(tx accountSessionTransaction, now time.Time) error {
		var workspaceID, networkID string
		if err := tx.QueryRow(ctx, resolveLogoutScopeSQL, fingerprint[:], nodeKey[:]).Scan(&workspaceID,
			&networkID); err != nil {
			return deviceLogoutDatabaseError(err)
		}
		scope, err := parseLogoutScope(workspaceID, networkID)
		if err != nil {
			return err
		}
		var workspaceInternal, networkInternal int64
		if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, workspaceID, networkID).Scan(&workspaceInternal,
			&networkInternal); err != nil || workspaceInternal <= 0 || networkInternal <= 0 {
			return errors.Join(control.ErrDeviceLogoutNotFound, err)
		}
		var encoded string
		if err := tx.QueryRow(ctx, logoutDeviceSQL, fingerprint[:], nodeKey[:], changeID.String(),
			now).Scan(&encoded); err != nil {
			return deviceLogoutDatabaseError(err)
		}
		logout, err = appendDeviceLogoutEvidence(ctx, tx, scope, changeID, encoded)
		return err
	})
	if err != nil {
		return control.DeviceLogout{}, err
	}
	return logout, nil
}

// transact runs one transaction; run receives its time on the database
// clock, which every time it passes to SQL uses.
func (store *DeviceLogoutStore) transact(ctx context.Context,
	run func(tx accountSessionTransaction, now time.Time) error) (resultErr error) {
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return errors.Join(control.ErrDeviceLogoutUnavailable, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return errors.Join(control.ErrDeviceLogoutUnavailable, err)
	}
	now, err := readTransactionTime(ctx, tx.QueryRow)
	if err != nil {
		return errors.Join(control.ErrDeviceLogoutUnavailable, err)
	}
	if err := run(tx, now); err != nil {
		return err
	}
	committed = true
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(control.ErrDeviceLogoutUnavailable, err)
	}
	return nil
}

func parseLogoutScope(workspaceID, networkID string) (network.Scope, error) {
	workspacePublic, workspaceErr := workspace.ParseID(workspaceID)
	networkPublic, networkErr := network.ParseID(networkID)
	if workspaceErr != nil || networkErr != nil {
		return network.Scope{}, control.ErrDeviceLogoutUnavailable
	}
	scope, err := network.NewScope(workspacePublic, networkPublic)
	if err != nil {
		return network.Scope{}, control.ErrDeviceLogoutUnavailable
	}
	return scope, nil
}

type deviceLogoutRecord struct {
	Before            json.RawMessage `json:"before"`
	After             json.RawMessage `json:"after"`
	ActorPrincipalID  string          `json:"actor_principal_id"`
	NetworkRevision   int64           `json:"network_revision"`
	InventoryRevision int64           `json:"inventory_revision"`
	GroupRevision     int64           `json:"group_revision"`
}

// appendDeviceLogoutEvidence validates what the function returned and seals
// device.logged_out with a revision wakeup.
func appendDeviceLogoutEvidence(ctx context.Context, tx accountSessionTransaction, scope network.Scope,
	changeID publicid.ID, encoded string) (control.DeviceLogout, error) {
	var record deviceLogoutRecord
	if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil || record.NetworkRevision <= 0 ||
		record.InventoryRevision <= 0 || record.GroupRevision <= 0 {
		return control.DeviceLogout{}, control.ErrDeviceLogoutUnavailable
	}
	var before, after deviceLifecycleDocument
	if decodeIdentityCatalogJSON(record.Before, &before) != nil || decodeIdentityCatalogJSON(record.After, &after) != nil {
		return control.DeviceLogout{}, control.ErrDeviceLogoutUnavailable
	}
	beforeState, beforeErr := before.state()
	afterState, afterErr := after.state()
	actor, actorErr := publicid.Parse(record.ActorPrincipalID)
	if beforeErr != nil || afterErr != nil || actorErr != nil || afterState.DeviceID != beforeState.DeviceID ||
		afterState.State != "revoked" || afterState.Version <= beforeState.Version {
		return control.DeviceLogout{}, control.ErrDeviceLogoutUnavailable
	}
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`).Scan(&streamID, &sequence, &previous); err != nil {
		return control.DeviceLogout{}, errors.Join(control.ErrDeviceLogoutUnavailable, err)
	}
	beforeHash := sha256.Sum256(record.Before)
	event := catalogEvent{
		correlationID: changeID, changeID: changeID, aggregateKind: "device",
		aggregateID: publicid.ID(afterState.DeviceID), version: afterState.Version,
		networkVersion: record.NetworkRevision, action: "device.logged_out", permission: deviceLogoutPermission,
		before: &beforeHash, after: sha256.Sum256(record.After), actor: actor,
		payload: struct {
			NetworkID  string          `json:"network_id"`
			DeviceID   string          `json:"device_id"`
			DeviceName string          `json:"display_name"`
			Initiator  string          `json:"initiator"`
			Before     json.RawMessage `json:"before"`
			After      json.RawMessage `json:"after"`
		}{scope.NetworkID().String(), afterState.DeviceID.String(), afterState.Hostname, "device", record.Before,
			record.After},
		outboxClass: "network.revision.advanced",
		outbox: struct {
			NetworkID         string `json:"network_id"`
			DeviceID          string `json:"device_id"`
			NetworkRevision   int64  `json:"network_revision"`
			InventoryRevision int64  `json:"inventory_revision"`
			GroupRevision     int64  `json:"group_revision"`
		}{scope.NetworkID().String(), afterState.DeviceID.String(), record.NetworkRevision,
			record.InventoryRevision, record.GroupRevision},
	}
	if err := appendCatalogEvent(ctx, tx, streamID, sequence, previous, event); err != nil {
		return control.DeviceLogout{}, errors.Join(control.ErrDeviceLogoutUnavailable, err)
	}
	return control.DeviceLogout{Scope: scope, DeviceID: afterState.DeviceID, NetworkRevision: record.NetworkRevision}, nil
}

func deviceLogoutDatabaseError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return control.ErrDeviceLogoutNotFound
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "P0002", "42501":
			return control.ErrDeviceLogoutNotFound
		}
	}
	return errors.Join(control.ErrDeviceLogoutUnavailable, err)
}

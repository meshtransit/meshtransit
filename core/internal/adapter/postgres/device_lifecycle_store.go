package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/meshtransit/meshtransit/core/internal/domain/devicelifecycle"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

const changeDeviceLifecycleSQL = `SELECT mesh_ops.change_device_lifecycle_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TEXT,$14::BIGINT,$15::UUID,$16::TEXT,$17::UUID,$18::TIMESTAMPTZ)::TEXT`

// DeviceLifecycleStore suspends, resumes, transfers and renames Devices
// through the runtime pool, committing each change with evidence on the
// Device's Network stream and the revision wakeup that rebuilds its maps.
type DeviceLifecycleStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ devicelifecycle.Store = (*DeviceLifecycleStore)(nil)

// NewDeviceLifecycleStore uses the runtime pool.
func NewDeviceLifecycleStore(pool *Pool, options AccountSessionOptions) (*DeviceLifecycleStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, devicelifecycle.ErrInvalid
	}
	return &DeviceLifecycleStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

// transact runs one exact-Network transaction and commits only when run asks.
func (store *DeviceLifecycleStore) transact(ctx context.Context, scope network.Scope,
	run func(tx accountSessionTransaction) (bool, error)) (resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return devicelifecycle.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return errors.Join(devicelifecycle.ErrUnavailable, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return errors.Join(devicelifecycle.ErrUnavailable, err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
		return deviceLifecycleDatabaseError(err)
	}
	if workspaceInternal <= 0 || networkInternal <= 0 {
		return devicelifecycle.ErrForbidden
	}
	commit, err := run(tx)
	if err != nil || !commit {
		return err
	}
	committed = true
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(devicelifecycle.ErrUnavailable, err)
	}
	return nil
}

func deviceLifecycleDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501", "23503":
			return devicelifecycle.ErrForbidden
		case "P0002":
			return devicelifecycle.ErrNotFound
		case "40001":
			return devicelifecycle.ErrVersionConflict
		case "MTL01":
			return devicelifecycle.ErrWrongState
		case "MTL02":
			return devicelifecycle.ErrIneligibleOwner
		case "MTL03", "23505":
			return devicelifecycle.ErrHostnameTaken
		case "22023", "22P02", "23514":
			return devicelifecycle.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return devicelifecycle.ErrForbidden
	}
	return errors.Join(devicelifecycle.ErrUnavailable, err)
}

type deviceLifecycleDocument struct {
	DeviceID        string    `json:"device_id"`
	Hostname        string    `json:"hostname"`
	State           string    `json:"state"`
	Ownership       string    `json:"ownership"`
	Owner           *string   `json:"owner_principal_id"`
	SuspendedReason *string   `json:"suspended_reason"`
	HandoverTo      *string   `json:"handover_principal_id"`
	HostnameLocked  bool      `json:"hostname_locked"`
	ExpiresAt       time.Time `json:"expires_at"`
	Version         int64     `json:"version"`
}

func (document deviceLifecycleDocument) state() (devicelifecycle.State, error) {
	device, err := node.ParseID(document.DeviceID)
	if err != nil || document.Version < 1 || document.ExpiresAt.IsZero() {
		return devicelifecycle.State{}, devicelifecycle.ErrInvalid
	}
	state := devicelifecycle.State{
		DeviceID: device, Hostname: document.Hostname, State: document.State,
		Ownership: devicelifecycle.Ownership(document.Ownership), HostnameLocked: document.HostnameLocked,
		ExpiresAt: document.ExpiresAt, Version: document.Version,
	}
	switch state.Ownership {
	case devicelifecycle.OwnershipMember:
		if document.Owner == nil {
			return devicelifecycle.State{}, devicelifecycle.ErrInvalid
		}
		if state.Owner, err = publicid.Parse(*document.Owner); err != nil {
			return devicelifecycle.State{}, devicelifecycle.ErrInvalid
		}
	case devicelifecycle.OwnershipWorkspace:
		if document.Owner != nil {
			return devicelifecycle.State{}, devicelifecycle.ErrInvalid
		}
	default:
		return devicelifecycle.State{}, devicelifecycle.ErrInvalid
	}
	if document.SuspendedReason != nil {
		state.SuspendedReason = devicelifecycle.SuspendedReason(*document.SuspendedReason)
	}
	if document.HandoverTo != nil {
		if state.HandoverTo, err = publicid.Parse(*document.HandoverTo); err != nil {
			return devicelifecycle.State{}, devicelifecycle.ErrInvalid
		}
	}
	if (state.State == "suspended") != (state.SuspendedReason != "") ||
		(state.SuspendedReason == devicelifecycle.SuspendedForHandover) != state.HandoverTo.IsValid() {
		return devicelifecycle.State{}, devicelifecycle.ErrInvalid
	}
	return state, nil
}

// deviceLifecycleAction is the audit action of each change.
var deviceLifecycleAction = map[devicelifecycle.Action]string{
	devicelifecycle.ActionSuspend:           "device.suspended",
	devicelifecycle.ActionResume:            "device.reactivated",
	devicelifecycle.ActionTransferWorkspace: "device.ownership_transferred",
	devicelifecycle.ActionTransferMember:    "device.handover_started",
	devicelifecycle.ActionRename:            "device.renamed",
}

// Change authorizes and applies one lifecycle change.
func (store *DeviceLifecycleStore) Change(ctx context.Context, change devicelifecycle.Change) (
	devicelifecycle.Result, error) {
	action, known := deviceLifecycleAction[change.Action]
	if store == nil || !change.IsValid() || !known {
		return devicelifecycle.Result{}, devicelifecycle.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return devicelifecycle.Result{}, devicelifecycle.ErrUnavailable
	}
	var newOwner, hostname any
	if change.NewOwner.IsValid() {
		newOwner = change.NewOwner.String()
	}
	if change.Hostname.IsValid() {
		hostname = change.Hostname.String()
	}
	scope := change.Scope
	var result devicelifecycle.Result
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, changeDeviceLifecycleSQL, append(sessionQueryArguments(change.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), change.DeviceID.String(),
			string(change.Action), change.ExpectedVersion, newOwner, hostname, changeID.String(),
			change.EvaluatedAt)...).Scan(&encoded); err != nil {
			return false, deviceLifecycleDatabaseError(err)
		}
		var record struct {
			Before            json.RawMessage `json:"before"`
			After             json.RawMessage `json:"after"`
			NetworkRevision   int64           `json:"network_revision"`
			InventoryRevision int64           `json:"inventory_revision"`
			GroupRevision     int64           `json:"group_revision"`
			RoleBindingID     *string         `json:"role_binding_id"`
			Permission        string          `json:"permission"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil || record.NetworkRevision <= 0 ||
			record.InventoryRevision <= 0 || record.GroupRevision <= 0 || record.Permission == "" {
			return false, devicelifecycle.ErrInvalid
		}
		var before, after deviceLifecycleDocument
		if decodeIdentityCatalogJSON(record.Before, &before) != nil || decodeIdentityCatalogJSON(record.After, &after) != nil {
			return false, devicelifecycle.ErrInvalid
		}
		beforeState, err := before.state()
		if err != nil {
			return false, err
		}
		afterState, err := after.state()
		if err != nil || afterState.DeviceID != change.DeviceID || beforeState.DeviceID != change.DeviceID ||
			afterState.Version != beforeState.Version+1 {
			return false, devicelifecycle.ErrInvalid
		}
		result = devicelifecycle.Result{Before: beforeState, After: afterState, NetworkRevision: record.NetworkRevision}
		binding := ""
		if record.RoleBindingID != nil {
			binding = *record.RoleBindingID
		}
		var streamID, sequence int64
		var previous []byte
		if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`).Scan(&streamID, &sequence, &previous); err != nil {
			return false, errors.Join(devicelifecycle.ErrUnavailable, err)
		}
		beforeHash := sha256.Sum256(record.Before)
		event := catalogEvent{
			session: change.Session, correlationID: change.CorrelationID, changeID: changeID,
			aggregateKind: "device", aggregateID: publicid.ID(change.DeviceID), version: afterState.Version,
			networkVersion: record.NetworkRevision, action: action, permission: record.Permission,
			before: &beforeHash, after: sha256.Sum256(record.After),
			payload: struct {
				NetworkID     string          `json:"network_id"`
				SessionID     string          `json:"session_id"`
				RoleBindingID string          `json:"role_binding_id,omitempty"`
				DeviceID      string          `json:"device_id"`
				DeviceName    string          `json:"display_name"`
				Reason        string          `json:"reason,omitempty"`
				Before        json.RawMessage `json:"before"`
				After         json.RawMessage `json:"after"`
			}{scope.NetworkID().String(), change.Session.ID().String(), binding, change.DeviceID.String(),
				afterState.Hostname, change.Reason, record.Before, record.After},
			outboxClass: "network.revision.advanced",
			outbox: struct {
				NetworkID         string `json:"network_id"`
				DeviceID          string `json:"device_id"`
				NetworkRevision   int64  `json:"network_revision"`
				InventoryRevision int64  `json:"inventory_revision"`
				GroupRevision     int64  `json:"group_revision"`
			}{scope.NetworkID().String(), change.DeviceID.String(), record.NetworkRevision,
				record.InventoryRevision, record.GroupRevision},
		}
		if err := appendCatalogEvent(ctx, tx, streamID, sequence, previous, event); err != nil {
			return false, errors.Join(devicelifecycle.ErrUnavailable, err)
		}
		return true, nil
	})
	if err != nil {
		return devicelifecycle.Result{}, err
	}
	return result, nil
}

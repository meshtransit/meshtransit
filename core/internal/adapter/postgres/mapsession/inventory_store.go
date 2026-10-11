package mapsession

import (
	"context"
	"errors"
	"fmt"
	"time"

	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
)

// loadInventoryRevisionSQL reads the revision the inventory read belongs to
// and the PostgreSQL time it is read at, in the installed exact scope.
const loadInventoryRevisionSQL = `SELECT revision.network_revision, pg_catalog.transaction_timestamp()
FROM mesh_ops.network_revision AS revision
WHERE revision.workspace_id = mesh_ops.current_workspace_id()
  AND revision.network_id = mesh_ops.current_network_id()`

// loadNetworkDevicesSQL reads every live Device of the installed scope
// (schema 140), with the liveness filters of the per-Device candidate read.
const loadNetworkDevicesSQL = `SELECT
    numeric_node_id,
    numeric_owner_id,
    node_public_id::TEXT,
    owner_public_id::TEXT,
    hostname,
    machine_key,
    node_key,
    session_generation,
    created_at,
    key_expiry,
    addresses
FROM mesh_ops.load_map_network_devices_v1($1::INTEGER)`

// readInventory reads one Network's whole live inventory in its own
// read-only repeatable-read transaction, with the inventory statement bound.
func (store *Store) readInventory(
	ctx context.Context,
	scope network.Scope,
	workspaceValue string,
	networkValue string,
) (cached cachedInventory, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observer.ObserveMapSession(OperationLoadInventory, time.Since(startedAt), resultErr)
	}()
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return cachedInventory{}, errors.Join(ErrLoadSnapshot, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollback(transaction))
		}
	}()
	if err := transaction.Exec(ctx, configureTransactionSQL,
		postgresTimeout(store.options.InventoryStatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return cachedInventory{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("configure inventory read: %w", err))
	}
	var workspaceInternalID, networkInternalID int64
	if err := transaction.QueryRow(ctx, setScopeSQL, workspaceValue, networkValue).Scan(
		&workspaceInternalID, &networkInternalID); err != nil {
		return cachedInventory{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("set inventory scope: %w", err))
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return cachedInventory{}, ErrSnapshotEvidence
	}
	if err := transaction.QueryRow(ctx, loadInventoryRevisionSQL).Scan(&cached.revision, &cached.readAt); err != nil {
		return cachedInventory{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("read inventory revision: %w", err))
	}
	if cached.revision <= 0 || cached.readAt.IsZero() {
		return cachedInventory{}, ErrSnapshotEvidence
	}
	devices, err := store.readNetworkDevices(ctx, transaction, scope)
	if err != nil {
		return cachedInventory{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return cachedInventory{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("commit inventory read: %w", err))
	}
	committed = true
	cached.inventory, err = appmapsession.NewNetworkInventory(scope, devices)
	if err != nil {
		return cachedInventory{}, errors.Join(ErrSnapshotEvidence, err)
	}
	for _, device := range devices {
		if cached.expiresAt.IsZero() || device.KeyExpiry().Before(cached.expiresAt) {
			cached.expiresAt = device.KeyExpiry()
		}
	}
	return cached, nil
}

func (store *Store) readNetworkDevices(
	ctx context.Context,
	transaction databaseTransaction,
	scope network.Scope,
) ([]appmapsession.PeerCandidate, error) {
	rows, err := transaction.Query(ctx, loadNetworkDevicesSQL, appmapsession.MaximumNetworkDevices+1)
	if err != nil || rows == nil {
		if err == nil {
			err = ErrSnapshotEvidence
		}
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network inventory: %w", err))
	}
	defer rows.Close()
	devices := make([]appmapsession.PeerCandidate, 0, 256)
	for rows.Next() {
		if len(devices) == appmapsession.MaximumNetworkDevices {
			return nil, errors.Join(ErrLoadSnapshot, appmapsession.ErrPeerCandidateLimit)
		}
		var record peerCandidateRecord
		if err := rows.Scan(
			&record.numericNodeID,
			&record.numericOwnerID,
			&record.nodeID,
			&record.ownerID,
			&record.hostname,
			&record.machineKey,
			&record.nodeKey,
			&record.sessionGeneration,
			&record.createdAt,
			&record.keyExpiry,
			&record.addresses,
		); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network inventory: %w", err))
		}
		device, err := record.candidate(scope)
		if err != nil {
			return nil, err
		}
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate network inventory: %w", err))
	}
	return devices, nil
}

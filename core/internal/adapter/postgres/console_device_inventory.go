package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/inventory"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// readConsoleDeviceInventorySQL reads v2 with each Device's DNS label and
// the scope's display codes (schema 169).
const readConsoleDeviceInventorySQL = `SELECT mesh_ops.read_console_devices_v3(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TIMESTAMPTZ, $13::UUID, $14::INTEGER
)::TEXT`

// ConsoleDeviceInventoryStore owns bounded reads with authorization row locks.
type ConsoleDeviceInventoryStore struct {
	database resourceAuthorityDatabase
	options  AccountSessionOptions
	metrics  *postgresPoolMetrics
}

// NewConsoleDeviceInventoryStore accepts only the runtime-authenticated pool.
func NewConsoleDeviceInventoryStore(pool *Pool, options AccountSessionOptions) (*ConsoleDeviceInventoryStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil || !validAccountSessionOptions(options) {
		return nil, inventory.ErrUnavailable
	}
	return &ConsoleDeviceInventoryStore{database: pool.resourceAuthorityDatabase, options: options, metrics: pool.metrics}, nil
}

// ReadDevices loads a bounded exact-scope page after current device.read checks,
// rerun on a fresh snapshot when a concurrent change holds the revision row.
func (store *ConsoleDeviceInventoryStore) ReadDevices(ctx context.Context, session accountsession.Session,
	scope network.Scope, after node.ID, limit int, evaluatedAt time.Time,
) (inventory.ReadResult, error) {
	return retryReadConflict(ctx, func() (inventory.ReadResult, error) {
		return store.readDevicesOnce(ctx, session, scope, after, limit, evaluatedAt)
	})
}

func (store *ConsoleDeviceInventoryStore) readDevicesOnce(ctx context.Context, session accountsession.Session,
	scope network.Scope, after node.ID, limit int, evaluatedAt time.Time,
) (_ inventory.ReadResult, resultErr error) {
	startedAt := time.Now()
	defer func() {
		if store != nil && store.metrics != nil {
			store.metrics.observeOperation(postgresOperationConsoleDeviceInventory, time.Since(startedAt), resultErr)
		}
	}()
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) ||
		!session.IsValid() || !scope.IsValid() || (!after.IsValid() && after != (node.ID{})) ||
		limit < 1 || limit > inventory.MaximumPageSize+1 || evaluatedAt.IsZero() {
		return inventory.ReadResult{}, inventory.ErrInvalidRequest
	}
	// RBAC and revision FOR SHARE locks require a read-write transaction; the
	// invoked function has no mutation statements or new write privileges.
	transaction, err := store.database.BeginRepeatableRead(ctx)
	if err != nil || transaction == nil {
		return inventory.ReadResult{}, errors.Join(inventory.ErrUnavailable, err)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceAuthoritySetup(transaction))
		}
	}()
	if err := transaction.Exec(ctx, configureAccountSessionReadTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout),
	); err != nil {
		return inventory.ReadResult{}, errors.Join(inventory.ErrUnavailable, err)
	}
	if err := transaction.Exec(ctx, `SELECT pg_catalog.set_config('lock_timeout', $1, TRUE)`,
		postgresTimeout(store.options.StatementTimeout),
	); err != nil {
		return inventory.ReadResult{}, errors.Join(inventory.ErrUnavailable, err)
	}
	var afterValue any
	if after.IsValid() {
		afterValue = after.String()
	}
	var encoded *string
	err = transaction.QueryRow(ctx, readConsoleDeviceInventorySQL,
		session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		scope.WorkspaceID().String(), scope.NetworkID().String(), evaluatedAt, afterValue, limit,
	).Scan(&encoded)
	if err != nil {
		return inventory.ReadResult{}, errors.Join(inventory.ErrUnavailable, err)
	}
	if encoded == nil {
		return inventory.ReadResult{}, inventory.ErrForbidden
	}
	result, err := decodeConsoleDeviceInventory(*encoded)
	if err != nil {
		return inventory.ReadResult{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return inventory.ReadResult{}, errors.Join(inventory.ErrUnavailable, err)
	}
	closed = true
	return result, nil
}

type consoleDeviceInventoryWire struct {
	WorkspaceID string `json:"workspace_id"`
	NetworkID   string `json:"network_id"`
	Revision    int64  `json:"inventory_revision"`
	// Schema 169: the scope's display codes.
	WorkspaceCode string `json:"workspace_code"`
	NetworkCode   string `json:"network_code"`
	Devices       []struct {
		ID        string    `json:"id"`
		Hostname  string    `json:"hostname"`
		State     string    `json:"state"`
		Ephemeral *bool     `json:"is_ephemeral"`
		Version   int64     `json:"version"`
		CreatedAt time.Time `json:"created_at"`
		UpdatedAt time.Time `json:"updated_at"`
		ExpiresAt time.Time `json:"expires_at"`
		// Schema 125 lifecycle.
		Ownership       string                        `json:"ownership"`
		Owner           *consoleDeviceInventoryMember `json:"owner"`
		SuspendedReason *string                       `json:"suspended_reason"`
		HandoverTo      *consoleDeviceInventoryMember `json:"handover_to"`
		// Schema 169: null for a Device that holds no label (revoked).
		DNSLabel *string `json:"dns_label"`
	} `json:"devices"`
}

type consoleDeviceInventoryMember struct {
	PrincipalID string `json:"principal_id"`
	DisplayName string `json:"display_name"`
}

func (member *consoleDeviceInventoryMember) parse() (inventory.Member, bool) {
	if member == nil {
		return inventory.Member{}, true
	}
	id, err := publicid.Parse(member.PrincipalID)
	return inventory.Member{PrincipalID: id, DisplayName: member.DisplayName}, err == nil && len(member.DisplayName) <= 255
}

func decodeConsoleDeviceInventory(encoded string) (inventory.ReadResult, error) {
	if len(encoded) > 1024*1024 {
		return inventory.ReadResult{}, inventory.ErrInvalidResult
	}
	var wire consoleDeviceInventoryWire
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&wire) != nil || wire.Devices == nil || len(wire.Devices) > inventory.MaximumPageSize+1 {
		return inventory.ReadResult{}, inventory.ErrInvalidResult
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return inventory.ReadResult{}, inventory.ErrInvalidResult
	}
	workspaceID, workspaceErr := workspace.ParseID(wire.WorkspaceID)
	networkID, networkErr := network.ParseID(wire.NetworkID)
	scope, scopeErr := network.NewScope(workspaceID, networkID)
	if workspaceErr != nil || networkErr != nil || scopeErr != nil || wire.Revision < 1 {
		return inventory.ReadResult{}, inventory.ErrInvalidResult
	}
	workspaceCode, workspaceCodeErr := identity.ParseDisplayCode(wire.WorkspaceCode)
	networkCode, networkCodeErr := identity.ParseDisplayCode(wire.NetworkCode)
	if workspaceCodeErr != nil || networkCodeErr != nil {
		return inventory.ReadResult{}, inventory.ErrInvalidResult
	}
	result := inventory.ReadResult{Scope: scope, Revision: wire.Revision, Devices: make([]inventory.Device, len(wire.Devices)),
		WorkspaceCode: workspaceCode, NetworkCode: networkCode}
	for index, item := range wire.Devices {
		if item.Ephemeral == nil {
			return inventory.ReadResult{}, inventory.ErrInvalidResult
		}
		id, idErr := node.ParseID(item.ID)
		hostname, hostnameErr := node.ParseHostname(item.Hostname)
		device, deviceErr := inventory.NewDevice(id, hostname, item.State, *item.Ephemeral,
			item.Version, item.CreatedAt, item.UpdatedAt, item.ExpiresAt)
		owner, ownerOK := item.Owner.parse()
		handover, handoverOK := item.HandoverTo.parse()
		if idErr != nil || hostnameErr != nil || deviceErr != nil || !ownerOK || !handoverOK {
			return inventory.ReadResult{}, inventory.ErrInvalidResult
		}
		lifecycle := inventory.Lifecycle{Ownership: item.Ownership, Owner: owner, HandoverTo: handover}
		if item.SuspendedReason != nil {
			lifecycle.SuspendedReason = *item.SuspendedReason
		}
		if device, deviceErr = device.WithLifecycle(lifecycle); deviceErr != nil {
			return inventory.ReadResult{}, inventory.ErrInvalidResult
		}
		if item.DNSLabel != nil {
			label, labelErr := node.ParseDNSLabel(*item.DNSLabel)
			if labelErr != nil {
				return inventory.ReadResult{}, inventory.ErrInvalidResult
			}
			if device, deviceErr = device.WithDNSLabel(label); deviceErr != nil {
				return inventory.ReadResult{}, inventory.ErrInvalidResult
			}
		}
		result.Devices[index] = device
	}
	return result, nil
}

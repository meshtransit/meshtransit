package mapsession

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	appmapsession "meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

// loadInventoryRevisionSQL reads the revision the inventory read belongs to
// and the PostgreSQL time it is read at, in the installed exact scope.
const loadInventoryRevisionSQL = `SELECT revision.network_revision, revision.policy_revision,
    pg_catalog.transaction_timestamp(),
    EXISTS (
        SELECT 1 FROM mesh.policy_release AS release
        WHERE release.workspace_id = revision.workspace_id
          AND release.network_id = revision.network_id
          AND release.policy_revision = revision.policy_revision
          AND release.state = 'active'
    )
FROM mesh_ops.network_revision AS revision
WHERE revision.workspace_id = mesh_ops.current_workspace_id()
  AND revision.network_id = mesh_ops.current_network_id()`

// The Network's packet policy at selector level (schema 141).
const (
	loadNetworkPolicyRulesSQL = `SELECT rule_kind, access_rule_public_id::TEXT, source_kind, source_ref,
    destination_kind, destination_ref, protocol, port_first, port_last
FROM mesh_ops.load_map_network_policy_rules_v1($1::BIGINT, $2::INTEGER)`
	loadNetworkSelectorMembersSQL = `SELECT selector_kind, selector_id, device_id, valid_until
FROM mesh_ops.load_map_network_selector_members_v1($1::INTEGER)`
	loadNetworkPolicyDevicesSQL = `SELECT device_id, device_public_id::TEXT, expires_at
FROM mesh_ops.load_map_network_policy_devices_v1($1::INTEGER)`
	// Bounds of one Network policy read: rules of a release, selector
	// memberships (a Device may sit in several selectors) and Devices.
	maximumNetworkPolicyRules   = 1_000_000
	maximumNetworkMemberships   = 10_000_000
	maximumNetworkPolicyDevices = 1_000_000

	// Whether the Network takes part in a Device share (schema 145).
	loadNetworkSharingSQL = `SELECT mesh_ops.map_network_has_sharing_v1()`
	loadNetworkHeaderSQL  = `SELECT network_display_name, recovery_epoch
FROM mesh_ops.load_map_network_header_v1()`
)

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
	var policyRevision int64
	var releaseActive bool
	if err := transaction.QueryRow(ctx, loadInventoryRevisionSQL).Scan(
		&cached.revision, &policyRevision, &cached.readAt, &releaseActive); err != nil {
		return cachedInventory{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("read inventory revision: %w", err))
	}
	if cached.revision <= 0 || policyRevision <= 0 || cached.readAt.IsZero() {
		return cachedInventory{}, ErrSnapshotEvidence
	}
	if err := readNetworkHeader(ctx, transaction, &cached); err != nil {
		return cachedInventory{}, err
	}
	if err := transaction.QueryRow(ctx, loadNetworkSharingSQL).Scan(&cached.sharing); err != nil {
		return cachedInventory{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network sharing: %w", err))
	}
	devices, err := store.readNetworkDevices(ctx, transaction, scope)
	if err != nil {
		return cachedInventory{}, err
	}
	cached.policy, err = readNetworkPolicy(ctx, transaction, scope, policyRevision, releaseActive)
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
	if changes := cached.policy.ChangesAt(); !changes.IsZero() && (cached.expiresAt.IsZero() || changes.Before(cached.expiresAt)) {
		cached.expiresAt = changes
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

// readNetworkPolicy reads one Network's policy at selector level within the
// inventory transaction, so both describe the same committed state.
func readNetworkPolicy(
	ctx context.Context,
	transaction databaseTransaction,
	scope network.Scope,
	revision int64,
	releaseActive bool,
) (appmapsession.NetworkPolicy, error) {
	params := appmapsession.NetworkPolicyParams{Scope: scope, Revision: revision, ReleaseActive: releaseActive}
	var err error
	if params.Rules, err = readNetworkPolicyRules(ctx, transaction, revision); err != nil {
		return appmapsession.NetworkPolicy{}, err
	}
	if params.Members, err = readNetworkSelectorMembers(ctx, transaction); err != nil {
		return appmapsession.NetworkPolicy{}, err
	}
	if params.Devices, err = readNetworkPolicyDevices(ctx, transaction); err != nil {
		return appmapsession.NetworkPolicy{}, err
	}
	networkPolicy, err := appmapsession.NewNetworkPolicy(params)
	if err != nil {
		return appmapsession.NetworkPolicy{}, errors.Join(ErrSnapshotEvidence, err)
	}
	return networkPolicy, nil
}

func readNetworkPolicyRules(
	ctx context.Context,
	transaction databaseTransaction,
	revision int64,
) ([]appmapsession.NetworkPolicyRule, error) {
	rows, err := transaction.Query(ctx, loadNetworkPolicyRulesSQL, revision, maximumNetworkPolicyRules+1)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network policy rules: %w", nonNil(err)))
	}
	defer rows.Close()
	rules := make([]appmapsession.NetworkPolicyRule, 0, 16)
	for rows.Next() {
		if len(rules) == maximumNetworkPolicyRules {
			return nil, errors.Join(ErrLoadSnapshot, appmapsession.ErrPacketPolicyLimit)
		}
		var record networkPolicyRuleRecord
		if err := rows.Scan(&record.ruleKind, &record.ruleID, &record.sourceKind, &record.sourceRef,
			&record.destinationKind, &record.destinationRef, &record.protocol, &record.portFirst, &record.portLast); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network policy rule: %w", err))
		}
		rule, err := record.rule()
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate network policy rules: %w", err))
	}
	return rules, nil
}

func readNetworkSelectorMembers(ctx context.Context, transaction databaseTransaction) ([]appmapsession.SelectorMember, error) {
	rows, err := transaction.Query(ctx, loadNetworkSelectorMembersSQL, maximumNetworkMemberships+1)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network selector members: %w", nonNil(err)))
	}
	defer rows.Close()
	members := make([]appmapsession.SelectorMember, 0, 64)
	for rows.Next() {
		if len(members) == maximumNetworkMemberships {
			return nil, errors.Join(ErrLoadSnapshot, appmapsession.ErrPacketPolicyLimit)
		}
		var kind string
		var validUntil *time.Time
		var member appmapsession.SelectorMember
		if err := rows.Scan(&kind, &member.Selector, &member.Device, &validUntil); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network selector member: %w", err))
		}
		member.Kind = selectorKindFromText(kind)
		if validUntil != nil {
			member.ValidUntil = *validUntil
		}
		members = append(members, member)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate network selector members: %w", err))
	}
	return members, nil
}

func readNetworkPolicyDevices(ctx context.Context, transaction databaseTransaction) ([]appmapsession.PolicyDevice, error) {
	rows, err := transaction.Query(ctx, loadNetworkPolicyDevicesSQL, maximumNetworkPolicyDevices+1)
	if err != nil || rows == nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network policy devices: %w", nonNil(err)))
	}
	defer rows.Close()
	devices := make([]appmapsession.PolicyDevice, 0, 256)
	for rows.Next() {
		if len(devices) == maximumNetworkPolicyDevices {
			return nil, errors.Join(ErrLoadSnapshot, appmapsession.ErrPeerCandidateLimit)
		}
		var publicID string
		var device appmapsession.PolicyDevice
		if err := rows.Scan(&device.Device, &publicID, &device.ExpiresAt); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network policy device: %w", err))
		}
		nodeID, err := node.ParseID(publicID)
		if err != nil {
			return nil, ErrSnapshotEvidence
		}
		device.NodeID = nodeID
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate network policy devices: %w", err))
	}
	return devices, nil
}

func nonNil(err error) error {
	if err == nil {
		return ErrSnapshotEvidence
	}
	return err
}

// readNetworkHeader reads the Network's display name and recovery epoch; no
// row leaves the inventory unable to serve maps.
func readNetworkHeader(ctx context.Context, transaction databaseTransaction, cached *cachedInventory) error {
	var name string
	err := transaction.QueryRow(ctx, loadNetworkHeaderSQL).Scan(&name, &cached.recoveryEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("read network header: %w", err))
	}
	displayName, err := network.ParseDisplayName(name)
	if err != nil || cached.recoveryEpoch <= 0 {
		return ErrSnapshotEvidence
	}
	cached.networkName, cached.serveable = displayName, true
	return nil
}

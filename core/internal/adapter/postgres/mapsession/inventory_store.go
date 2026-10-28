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
    revision.route_revision, pg_catalog.transaction_timestamp(),
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

	// The Devices whose maps a share changes (schema 146): a contract's
	// target, a rule source of an Imported Resource.
	loadNetworkSharingDevicesSQL = `SELECT COALESCE(pg_catalog.array_agg(device_id), '{}')
FROM mesh_ops.map_network_sharing_devices_v1($1::INTEGER)`
	// The header with the scope's display codes (schema 169).
	loadNetworkHeaderSQL = `SELECT header.network_display_name, header.recovery_epoch,
    codes.workspace_code, codes.network_code
FROM mesh_ops.load_map_network_header_v1() AS header
LEFT JOIN mesh_ops.read_scope_display_codes_v1() AS codes ON TRUE`

	// Whether the Network holds a legacy direct share endpoint (schema 154),
	// used once this role may run it.
	directEndpointsGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.map_network_has_direct_endpoints_v1()'), 'EXECUTE'), FALSE)`
	loadDirectEndpointsSQL = `SELECT mesh_ops.map_network_has_direct_endpoints_v1()`
)

// loadNetworkDevicesSQL reads every live Device of the installed scope
// (schema 140), with the liveness filters of the per-Device candidate read.
const loadNetworkDevicesSQL = `SELECT
    candidate.numeric_node_id,
    candidate.numeric_owner_id,
    candidate.node_public_id::TEXT,
    candidate.owner_public_id::TEXT,
    candidate.hostname,
    candidate.machine_key,
    candidate.node_key,
    candidate.session_generation,
    candidate.created_at,
    candidate.key_expiry,
    candidate.addresses,
    label.dns_label
FROM mesh_ops.load_map_network_devices_v1($1::INTEGER) AS candidate
` + scopedDNSLabelJoin

// The Network's change counter and the Devices changed after a counter
// (schema 153), used once this role may run them.
const (
	inventoryChangesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_device_changes_v1(bigint,integer)'), 'EXECUTE'), FALSE)
    AND COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.read_map_inventory_change_head_v1()'), 'EXECUTE'), FALSE)`
	loadInventoryChangeHeadSQL  = `SELECT mesh_ops.read_map_inventory_change_head_v1()`
	loadNetworkDeviceChangesSQL = `SELECT candidate.change_seq, candidate.numeric_node_id, candidate.listed,
    COALESCE(candidate.numeric_owner_id, 0), COALESCE(candidate.node_public_id::TEXT, ''),
    COALESCE(candidate.owner_public_id::TEXT, ''), COALESCE(candidate.hostname, ''),
    COALESCE(candidate.machine_key, ''::BYTEA), COALESCE(candidate.node_key, ''::BYTEA),
    COALESCE(candidate.session_generation, 0), COALESCE(candidate.created_at, 'epoch'::TIMESTAMPTZ),
    COALESCE(candidate.key_expiry, 'epoch'::TIMESTAMPTZ), COALESCE(candidate.addresses, '{}'::TEXT[]),
    label.dns_label
FROM mesh_ops.load_map_network_device_changes_v1($1::BIGINT, $2::INTEGER) AS candidate
` + scopedDNSLabelJoin + `
ORDER BY candidate.change_seq, candidate.numeric_node_id`

	// maximumInventoryChanges bounds one read of changed Devices; a Network
	// with more since the cached inventory is read whole.
	maximumInventoryChanges = 4096
	// inventoryFullReadInterval bounds how long an inventory is kept up to
	// date from changes alone before the Network is read whole again.
	inventoryFullReadInterval = 10 * time.Minute
)

// readInventory reads one Network's live inventory in its own read-only
// repeatable-read transaction, with the inventory statement bound. With
// previous, an inventory of the same Network that tracked its change
// counter, it reads only the Devices changed since and applies them; it
// reads the whole Network when there is no such inventory, when the
// Network's header changed, past maximumInventoryChanges, and at least every
// inventoryFullReadInterval.
func (store *Store) readInventory(
	ctx context.Context,
	scope network.Scope,
	workspaceValue string,
	networkValue string,
	previous cachedInventory,
) (cached cachedInventory, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observer.ObserveMapSession(OperationLoadInventory, time.Since(startedAt), resultErr)
	}()
	// This host's clock before the read: the read's database time is later,
	// so freshness and deadlines measured from it come early, never late.
	beginLocal := time.Now()
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
	var policyRevision, routeRevision int64
	var releaseActive bool
	if err := transaction.QueryRow(ctx, loadInventoryRevisionSQL).Scan(
		&cached.revision, &policyRevision, &routeRevision, &cached.readAt, &releaseActive); err != nil {
		return cachedInventory{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("read inventory revision: %w", err))
	}
	cached.readLocal = beginLocal
	if cached.revision <= 0 || policyRevision <= 0 || cached.readAt.IsZero() {
		return cachedInventory{}, ErrSnapshotEvidence
	}
	if err := readNetworkHeader(ctx, transaction, &cached); err != nil {
		return cachedInventory{}, err
	}
	if err := readSharingDevices(ctx, transaction, &cached); err != nil {
		return cachedInventory{}, err
	}
	if err := readDirectEndpoints(ctx, transaction, &cached); err != nil {
		return cachedInventory{}, err
	}
	if err := store.readInventoryDevices(ctx, transaction, scope, previous, &cached); err != nil {
		return cachedInventory{}, err
	}
	routes := networkRoutes{}
	if store.options.SubnetRoutes || store.options.ExitNodes || store.options.DNSZones {
		routes = networkRoutes{revision: routeRevision, peerLimit: store.options.RoutePeerLimit,
			sites: store.options.SubnetRoutes, exits: store.options.ExitNodes,
			spread: store.options.ExitNodes && store.options.ExitSpread, dnsZones: store.options.DNSZones,
			protected: store.options.protectedDNSNames()}
	}
	kubernetes := false
	if cached.clusters {
		if kubernetes, err = store.readsKubernetesSources(ctx, transaction); err != nil {
			return cachedInventory{}, err
		}
	}
	cached.policy, err = readNetworkPolicy(ctx, transaction, scope, policyRevision, releaseActive, routes,
		kubernetes)
	if err != nil {
		return cachedInventory{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return cachedInventory{}, errors.Join(ErrLoadSnapshot, fmt.Errorf("commit inventory read: %w", err))
	}
	committed = true
	cached.expiresAt = cached.inventory.EarliestKeyExpiry()
	if changes := cached.policy.ChangesAt(); !changes.IsZero() && (cached.expiresAt.IsZero() || changes.Before(cached.expiresAt)) {
		cached.expiresAt = changes
	}
	return cached, nil
}

// readInventoryDevices sets cached's inventory and change counter: previous
// with the Devices changed since applied when it can, else the whole
// Network.
func (store *Store) readInventoryDevices(
	ctx context.Context,
	transaction databaseTransaction,
	scope network.Scope,
	previous cachedInventory,
	cached *cachedInventory,
) error {
	cached.changeSeq = -1
	gateways, granted, err := store.readKubernetesGateways(ctx, transaction)
	if err != nil {
		return err
	}
	cached.gateways = granted
	cached.clusters = len(gateways) > 0
	tracked, err := functionGranted(ctx, transaction, inventoryChangesGrantedSQL)
	if err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("check inventory change reader: %w", err))
	}
	if tracked {
		if err := transaction.QueryRow(ctx, loadInventoryChangeHeadSQL).Scan(&cached.changeSeq); err != nil {
			return errors.Join(ErrLoadSnapshot, fmt.Errorf("read inventory change counter: %w", err))
		}
		if cached.changeSeq < 0 {
			return ErrSnapshotEvidence
		}
		if canApplyChanges(previous, *cached, scope) {
			applied, err := store.applyInventoryChanges(ctx, transaction, scope, previous, cached, gateways)
			if applied || ctx.Err() != nil {
				return err
			}
			if err != nil {
				// Changes that contradict the snapshot never block the Network:
				// read it whole (a failed statement fails that read too).
				store.stats.changeFallbacks.Add(1)
			}
		}
	}
	devices, err := store.readNetworkDevices(ctx, transaction, scope, gateways)
	if err != nil {
		return err
	}
	cached.inventory, err = appmapsession.NewNetworkInventory(scope, devices)
	if err != nil {
		return errors.Join(ErrSnapshotEvidence, err)
	}
	cached.fullReadAt = time.Now()
	return nil
}

// canApplyChanges reports whether cached may be previous with the Devices
// changed since applied: previous tracked the same Network's counter, which
// has not gone back, both serve maps under the same recovery epoch, both
// read gateway replicas alike, and the last whole read is recent.
func canApplyChanges(previous, cached cachedInventory, scope network.Scope) bool {
	return previous.inventory.IsValid() && previous.inventory.Scope() == scope &&
		previous.changeSeq >= 0 && cached.changeSeq >= previous.changeSeq &&
		previous.serveable && cached.serveable && previous.recoveryEpoch == cached.recoveryEpoch &&
		previous.gateways == cached.gateways &&
		!cached.readAt.Before(previous.readAt) && time.Since(previous.fullReadAt) < inventoryFullReadInterval
}

// applyInventoryChanges reads the Devices changed after previous's counter
// and applies them. applied is false when there are too many, or they do
// not fit one inventory, and the caller reads the whole Network.
func (store *Store) applyInventoryChanges(
	ctx context.Context,
	transaction databaseTransaction,
	scope network.Scope,
	previous cachedInventory,
	cached *cachedInventory,
	gateways kubernetesGateways,
) (bool, error) {
	var changes []appmapsession.InventoryChange
	if cached.changeSeq > previous.changeSeq {
		var complete bool
		var err error
		changes, complete, err = readNetworkDeviceChanges(ctx, transaction, scope, previous.changeSeq, cached.changeSeq,
			gateways)
		if err != nil || !complete {
			return false, err
		}
	}
	inventory, err := previous.inventory.WithChanges(changes, cached.readAt)
	if err != nil {
		return false, err // too many Devices or a conflict: the caller reads the whole Network
	}
	cached.inventory, cached.fullReadAt = inventory, previous.fullReadAt
	store.stats.changeReads.Add(1)
	return true, nil
}

// readNetworkDeviceChanges reads the Devices changed after since, up to the
// counter head of the same snapshot. complete is false past
// maximumInventoryChanges.
func readNetworkDeviceChanges(
	ctx context.Context,
	transaction databaseTransaction,
	scope network.Scope,
	since, head int64,
	gateways kubernetesGateways,
) ([]appmapsession.InventoryChange, bool, error) {
	rows, err := transaction.Query(ctx, loadNetworkDeviceChangesSQL, since, maximumInventoryChanges+1)
	if err != nil || rows == nil {
		return nil, false, errors.Join(ErrLoadSnapshot, fmt.Errorf("read network inventory changes: %w", nonNil(err)))
	}
	defer rows.Close()
	changes := make([]appmapsession.InventoryChange, 0, 16)
	for rows.Next() {
		if len(changes) == maximumInventoryChanges {
			return nil, false, nil
		}
		var changeSeq int64
		var listed bool
		var record peerCandidateRecord
		if err := rows.Scan(&changeSeq, &record.numericNodeID, &listed, &record.numericOwnerID, &record.nodeID,
			&record.ownerID, &record.hostname, &record.machineKey, &record.nodeKey, &record.sessionGeneration,
			&record.createdAt, &record.keyExpiry, &record.addresses, &record.dnsLabel); err != nil {
			return nil, false, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network inventory change: %w", err))
		}
		if changeSeq <= since || changeSeq > head || record.numericNodeID <= 0 {
			return nil, false, ErrSnapshotEvidence
		}
		change := appmapsession.InventoryChange{NumericNodeID: record.numericNodeID, Removed: !listed}
		if listed {
			gateways.mark(&record)
			if change.Device, err = record.candidate(scope); err != nil {
				return nil, false, err
			}
		}
		changes = append(changes, change)
	}
	if err := rows.Err(); err != nil {
		return nil, false, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate network inventory changes: %w", err))
	}
	return changes, true, nil
}

func (store *Store) readNetworkDevices(
	ctx context.Context,
	transaction databaseTransaction,
	scope network.Scope,
	gateways kubernetesGateways,
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
			&record.dnsLabel,
		); err != nil {
			return nil, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan network inventory: %w", err))
		}
		gateways.mark(&record)
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

// networkRoutes says whether a policy read also reads subnet routes (sites),
// Exit Pools (exits) and DNS zones: at route revision, cut at peerLimit;
// zero reads none.
type networkRoutes struct {
	revision  int64
	peerLimit int
	sites     bool
	exits     bool
	spread    bool
	dnsZones  bool
	protected []string // host names no zone may hold
}

// readNetworkPolicy reads one Network's policy at selector level within the
// inventory transaction, so both describe the same committed state, and its
// subnet routes when routes asks for them.
func readNetworkPolicy(
	ctx context.Context,
	transaction databaseTransaction,
	scope network.Scope,
	revision int64,
	releaseActive bool,
	routes networkRoutes,
	kubernetes bool,
) (appmapsession.NetworkPolicy, error) {
	params := appmapsession.NetworkPolicyParams{Scope: scope, Revision: revision, ReleaseActive: releaseActive}
	var err error
	if routes.revision > 0 && routes.peerLimit > 0 {
		params.RouteRevision, params.RoutePeerLimit = routes.revision, routes.peerLimit
		if routes.sites {
			if err := readNetworkRoutes(ctx, transaction, &params); err != nil {
				return appmapsession.NetworkPolicy{}, err
			}
		}
		if routes.exits {
			if err := readNetworkExits(ctx, transaction, &params, routes.spread); err != nil {
				return appmapsession.NetworkPolicy{}, err
			}
		}
		if routes.dnsZones {
			if err := readNetworkDNSZones(ctx, transaction, &params, routes.protected); err != nil {
				return appmapsession.NetworkPolicy{}, err
			}
		}
	}
	if params.Rules, err = readNetworkPolicyRules(ctx, transaction, revision); err != nil {
		return appmapsession.NetworkPolicy{}, err
	}
	if params.Members, err = readNetworkSelectorMembers(ctx, transaction); err != nil {
		return appmapsession.NetworkPolicy{}, err
	}
	if params.Devices, err = readNetworkPolicyDevices(ctx, transaction); err != nil {
		return appmapsession.NetworkPolicy{}, err
	}
	if kubernetes && releaseActive {
		if err := readKubernetesPolicy(ctx, transaction, revision, &params); err != nil {
			return appmapsession.NetworkPolicy{}, err
		}
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
// readSharingDevices records the Devices a share binds; their maps depend on
// state outside the view, so they are always read per Device.
func readSharingDevices(ctx context.Context, transaction databaseTransaction, cached *cachedInventory) error {
	var devices []int64
	if err := transaction.QueryRow(ctx, loadNetworkSharingDevicesSQL, maximumNetworkPolicyDevices+1).Scan(
		&devices); err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("read network sharing Devices: %w", err))
	}
	if len(devices) > maximumNetworkPolicyDevices {
		return ErrSnapshotEvidence
	}
	cached.sharingDevices = make(map[int64]struct{}, len(devices))
	for _, device := range devices {
		if device <= 0 {
			return ErrSnapshotEvidence
		}
		cached.sharingDevices[device] = struct{}{}
	}
	return nil
}

// readDirectEndpoints records whether the Network holds a legacy direct
// share endpoint; a database that cannot tell counts as holding one.
func readDirectEndpoints(ctx context.Context, transaction databaseTransaction, cached *cachedInventory) error {
	granted, err := functionGranted(ctx, transaction, directEndpointsGrantedSQL)
	if err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("check direct endpoint reader: %w", err))
	}
	cached.directEndpoints = true
	if !granted {
		return nil
	}
	if err := transaction.QueryRow(ctx, loadDirectEndpointsSQL).Scan(&cached.directEndpoints); err != nil {
		return errors.Join(ErrLoadSnapshot, fmt.Errorf("read network direct endpoints: %w", err))
	}
	return nil
}

func readNetworkHeader(ctx context.Context, transaction databaseTransaction, cached *cachedInventory) error {
	var name string
	var workspaceCode, networkCode *string
	err := transaction.QueryRow(ctx, loadNetworkHeaderSQL).Scan(&name, &cached.recoveryEpoch,
		&workspaceCode, &networkCode)
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
	cached.workspaceCode, cached.networkCode = optionalDisplayCodes(workspaceCode, networkCode)
	cached.networkName, cached.serveable = displayName, true
	return nil
}

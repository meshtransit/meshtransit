package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/memberlifecycle"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const listNetworkMembersSQL = `SELECT mesh_ops.list_network_members_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,NULLIF($12::TEXT,'')::UUID,$13::INTEGER,$14::TIMESTAMPTZ)::TEXT`

const addNetworkMembersSQL = `SELECT mesh_ops.add_network_members_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID[],$13::UUID,$14::TIMESTAMPTZ)::TEXT`

const removeNetworkMemberSQL = `SELECT mesh_ops.remove_network_member_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::JSONB,$14::UUID,$15::TIMESTAMPTZ)::TEXT`

const lockNetworkStreamHeadSQL = `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`

// networkMemberPermission authorizes every Network member change.
const networkMemberPermission = "network.member.manage"

// NetworkMemberStore lists, adds and removes the members of one Network
// through the runtime pool, in the transaction's exact Network scope. Each
// change commits with its evidence on the Network's stream; a removal also
// wakes the Network's map sessions.
type NetworkMemberStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ memberlifecycle.NetworkStore = (*NetworkMemberStore)(nil)

// NewNetworkMemberStore uses the runtime pool.
func NewNetworkMemberStore(pool *Pool, options AccountSessionOptions) (*NetworkMemberStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, memberlifecycle.ErrInvalid
	}
	return &NetworkMemberStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

// transact runs one exact-Network transaction and commits only when run asks.
func (store *NetworkMemberStore) transact(ctx context.Context, scope network.Scope,
	run func(tx accountSessionTransaction) (bool, error)) (resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return memberlifecycle.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return errors.Join(memberlifecycle.ErrUnavailable, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return errors.Join(memberlifecycle.ErrUnavailable, err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
		return memberLifecycleDatabaseError(err)
	}
	if workspaceInternal <= 0 || networkInternal <= 0 {
		return memberlifecycle.ErrForbidden
	}
	commit, err := run(tx)
	if err != nil || !commit {
		return err
	}
	committed = true
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(memberlifecycle.ErrUnavailable, err)
	}
	return nil
}

type networkMembershipDocument struct {
	MembershipID string    `json:"membership_id"`
	PrincipalID  string    `json:"principal_id"`
	State        string    `json:"state"`
	Version      int64     `json:"version"`
	AddedAt      time.Time `json:"added_at"`
}

func (document networkMembershipDocument) membership() (memberlifecycle.NetworkMembership, error) {
	membership, membershipErr := publicid.Parse(document.MembershipID)
	principal, principalErr := publicid.Parse(document.PrincipalID)
	if membershipErr != nil || principalErr != nil || document.Version < 1 || document.AddedAt.IsZero() ||
		(document.State != "active" && document.State != "suspended" && document.State != "revoked") {
		return memberlifecycle.NetworkMembership{}, memberlifecycle.ErrInvalid
	}
	return memberlifecycle.NetworkMembership{
		MembershipID: membership, PrincipalID: principal, State: document.State, Version: document.Version,
		AddedAt: document.AddedAt,
	}, nil
}

type networkMemberRow struct {
	PrincipalID    string                     `json:"principal_id"`
	DisplayName    string                     `json:"display_name"`
	WorkspaceState string                     `json:"workspace_membership_state"`
	Owner          bool                       `json:"owner"`
	Membership     *networkMembershipDocument `json:"network_membership"`
}

type networkMemberEnvelope struct {
	NetworkID string             `json:"network_id"`
	CanManage bool               `json:"can_manage"`
	Members   []networkMemberRow `json:"members"`
	HasMore   bool               `json:"has_more"`
}

// decode validates one page against the query: the right Network, at most
// the limit, strictly after the cursor and in principal order.
func (envelope networkMemberEnvelope) decode(query memberlifecycle.NetworkMemberQuery) (
	memberlifecycle.NetworkMemberPage, error) {
	if envelope.NetworkID != query.Scope.NetworkID().String() || envelope.Members == nil ||
		len(envelope.Members) > query.Limit || (envelope.HasMore && len(envelope.Members) == 0) {
		return memberlifecycle.NetworkMemberPage{}, memberlifecycle.ErrInvalid
	}
	page := memberlifecycle.NetworkMemberPage{
		CanManage: envelope.CanManage, HasMore: envelope.HasMore,
		Members: make([]memberlifecycle.NetworkMember, 0, len(envelope.Members)),
	}
	previous := ""
	if query.After.IsValid() {
		previous = query.After.String()
	}
	for _, row := range envelope.Members {
		principal, err := publicid.Parse(row.PrincipalID)
		if err != nil || principal.String() != row.PrincipalID || row.PrincipalID <= previous ||
			(row.WorkspaceState != "active" && row.WorkspaceState != "suspended") {
			return memberlifecycle.NetworkMemberPage{}, memberlifecycle.ErrInvalid
		}
		previous = row.PrincipalID
		member := memberlifecycle.NetworkMember{
			PrincipalID: principal, DisplayName: row.DisplayName, WorkspaceState: row.WorkspaceState,
			Owner: row.Owner,
		}
		if row.Membership != nil {
			membership, err := row.Membership.membership()
			if err != nil || membership.PrincipalID != principal || membership.State == "revoked" {
				return memberlifecycle.NetworkMemberPage{}, memberlifecycle.ErrInvalid
			}
			member.Membership = &membership
		}
		page.Members = append(page.Members, member)
	}
	return page, nil
}

// ListNetworkMembers authorizes network.read and returns one page.
func (store *NetworkMemberStore) ListNetworkMembers(ctx context.Context, query memberlifecycle.NetworkMemberQuery) (
	memberlifecycle.NetworkMemberPage, error) {
	if !query.IsValid() {
		return memberlifecycle.NetworkMemberPage{}, memberlifecycle.ErrInvalid
	}
	after := ""
	if query.After.IsValid() {
		after = query.After.String()
	}
	var page memberlifecycle.NetworkMemberPage
	err := store.transact(ctx, query.Scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, listNetworkMembersSQL, append(sessionQueryArguments(query.Session),
			query.Scope.WorkspaceID().String(), query.Scope.NetworkID().String(), after, query.Limit,
			query.EvaluatedAt)...).Scan(&encoded); err != nil {
			return false, memberLifecycleDatabaseError(err)
		}
		var envelope networkMemberEnvelope
		if err := decodeIdentityCatalogJSON([]byte(encoded), &envelope); err != nil {
			return false, memberlifecycle.ErrInvalid
		}
		decoded, err := envelope.decode(query)
		page = decoded
		// A read commits nothing.
		return false, err
	})
	if err != nil {
		return memberlifecycle.NetworkMemberPage{}, err
	}
	return page, nil
}

type networkAdditionRecord struct {
	NetworkID       string                      `json:"network_id"`
	NetworkRevision int64                       `json:"network_revision"`
	Added           []networkMembershipDocument `json:"added"`
	Unchanged       []string                    `json:"unchanged"`
	Authority       catalogAuthority            `json:"authority"`
}

// decode checks that every requested member is either added once, as a new
// active membership, or unchanged, and nothing else.
func (record networkAdditionRecord) decode(addition memberlifecycle.NetworkAddition) (
	memberlifecycle.NetworkAdditionResult, error) {
	if record.NetworkID != addition.Scope.NetworkID().String() || record.NetworkRevision <= 0 ||
		record.Added == nil || record.Unchanged == nil ||
		len(record.Added)+len(record.Unchanged) != len(addition.MemberIDs) {
		return memberlifecycle.NetworkAdditionResult{}, memberlifecycle.ErrInvalid
	}
	requested := make(map[publicid.ID]bool, len(addition.MemberIDs))
	for _, member := range addition.MemberIDs {
		requested[member] = true
	}
	result := memberlifecycle.NetworkAdditionResult{
		NetworkRevision: record.NetworkRevision,
		Added:           make([]memberlifecycle.NetworkMembership, 0, len(record.Added)),
		Unchanged:       make([]publicid.ID, 0, len(record.Unchanged)),
	}
	for _, document := range record.Added {
		membership, err := document.membership()
		if err != nil || membership.State != "active" || membership.Version != 1 || !requested[membership.PrincipalID] {
			return memberlifecycle.NetworkAdditionResult{}, memberlifecycle.ErrInvalid
		}
		delete(requested, membership.PrincipalID)
		result.Added = append(result.Added, membership)
	}
	for _, text := range record.Unchanged {
		member, err := publicid.Parse(text)
		if err != nil || !requested[member] {
			return memberlifecycle.NetworkAdditionResult{}, memberlifecycle.ErrInvalid
		}
		delete(requested, member)
		result.Unchanged = append(result.Unchanged, member)
	}
	return result, nil
}

func networkMembershipSemanticHash(networkID network.ID, membership memberlifecycle.NetworkMembership) (
	[32]byte, error) {
	encoded, err := json.Marshal(struct {
		NetworkID    string `json:"network_id"`
		MembershipID string `json:"membership_id"`
		PrincipalID  string `json:"principal_id"`
		State        string `json:"state"`
	}{networkID.String(), membership.MembershipID.String(), membership.PrincipalID.String(), membership.State})
	return sha256.Sum256(encoded), err
}

// appendNetworkMemberEvent records one event on the Network's own stream.
func appendNetworkMemberEvent(ctx context.Context, tx accountSessionTransaction, event catalogEvent) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, lockNetworkStreamHeadSQL).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	return appendCatalogEvent(ctx, tx, streamID, sequence, previous, event)
}

// AddNetworkMembers authorizes network.member.manage, adds the members not
// yet in the Network and records one event for each on the Network stream.
// Adding nobody new changes nothing and records nothing.
func (store *NetworkMemberStore) AddNetworkMembers(ctx context.Context, addition memberlifecycle.NetworkAddition) (
	memberlifecycle.NetworkAdditionResult, error) {
	if !addition.IsValid() {
		return memberlifecycle.NetworkAdditionResult{}, memberlifecycle.ErrInvalid
	}
	members := make([]string, len(addition.MemberIDs))
	for index, member := range addition.MemberIDs {
		members[index] = member.String()
	}
	changeID, err := publicid.New()
	if err != nil {
		return memberlifecycle.NetworkAdditionResult{}, memberlifecycle.ErrUnavailable
	}
	scope := addition.Scope
	var result memberlifecycle.NetworkAdditionResult
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, addNetworkMembersSQL, append(sessionQueryArguments(addition.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), members, changeID.String(),
			addition.EvaluatedAt)...).Scan(&encoded); err != nil {
			return false, memberLifecycleDatabaseError(err)
		}
		var record networkAdditionRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil {
			return false, memberlifecycle.ErrInvalid
		}
		decoded, err := record.decode(addition)
		if err != nil {
			return false, err
		}
		result = decoded
		for _, membership := range result.Added {
			event, err := networkMemberAddedEvent(addition, changeID, result.NetworkRevision, membership,
				record.Authority)
			if err != nil {
				return false, err
			}
			if err := appendNetworkMemberEvent(ctx, tx, event); err != nil {
				return false, errors.Join(memberlifecycle.ErrUnavailable, err)
			}
		}
		return len(result.Added) > 0, nil
	})
	if err != nil {
		return memberlifecycle.NetworkAdditionResult{}, err
	}
	return result, nil
}

func networkMemberAddedEvent(addition memberlifecycle.NetworkAddition, changeID publicid.ID, revision int64,
	membership memberlifecycle.NetworkMembership, authority catalogAuthority) (catalogEvent, error) {
	networkID := addition.Scope.NetworkID()
	after, err := networkMembershipSemanticHash(networkID, membership)
	if err != nil {
		return catalogEvent{}, err
	}
	return catalogEvent{
		session: addition.Session, correlationID: addition.CorrelationID, changeID: changeID,
		aggregateKind: "network_membership", aggregateID: membership.PrincipalID, version: membership.Version,
		networkVersion: revision, action: "network.member.added", permission: networkMemberPermission,
		after: after,
		payload: struct {
			NetworkID    string           `json:"network_id"`
			SessionID    string           `json:"session_id"`
			MemberID     string           `json:"member_principal_id"`
			MembershipID string           `json:"membership_id"`
			Authority    catalogAuthority `json:"authority"`
		}{networkID.String(), addition.Session.ID().String(), membership.PrincipalID.String(),
			membership.MembershipID.String(), authority},
		outboxClass: "network.member.added",
		outbox: struct {
			NetworkID    string `json:"network_id"`
			MemberID     string `json:"member_principal_id"`
			MembershipID string `json:"membership_id"`
			Version      int64  `json:"version"`
		}{networkID.String(), membership.PrincipalID.String(), membership.MembershipID.String(), membership.Version},
	}, nil
}

type networkRemovedDeviceRow struct {
	DeviceID string `json:"device_id"`
	Hostname string `json:"hostname"`
	Action   string `json:"action"`
	State    string `json:"state"`
}

type networkRemovalRecord struct {
	Before             networkMembershipDocument `json:"before"`
	After              networkMembershipDocument `json:"after"`
	Devices            []networkRemovedDeviceRow `json:"devices"`
	HandoversCancelled *int                      `json:"handovers_cancelled"`
	KeysRevoked        *int                      `json:"keys_revoked"`
	RolesRevoked       *int                      `json:"roles_revoked"`
	Networks           []advancedNetworkRow      `json:"networks"`
	Authority          catalogAuthority          `json:"authority"`
}

// decode validates the record against the removal: the member's membership
// revoked once, every planned Device handled as planned, every other Device
// revoked, and exactly this Network advanced.
func (record networkRemovalRecord) decode(removal memberlifecycle.NetworkRemoval) (
	memberlifecycle.NetworkRemovalResult, error) {
	before, err := record.Before.membership()
	if err != nil {
		return memberlifecycle.NetworkRemovalResult{}, err
	}
	after, err := record.After.membership()
	if err != nil || before.PrincipalID != removal.MemberID || after.PrincipalID != removal.MemberID ||
		before.MembershipID != after.MembershipID || before.State == "revoked" || after.State != "revoked" ||
		after.Version != before.Version+1 || record.Devices == nil ||
		!nonNegative(record.HandoversCancelled, record.KeysRevoked, record.RolesRevoked) {
		return memberlifecycle.NetworkRemovalResult{}, memberlifecycle.ErrInvalid
	}
	planned := make(map[node.ID]memberlifecycle.DeviceAction, len(removal.Devices))
	for _, plan := range removal.Devices {
		planned[plan.DeviceID] = plan.Action
	}
	devices := make([]memberlifecycle.RemovedDevice, 0, len(record.Devices))
	seen := make(map[node.ID]bool, len(record.Devices))
	for _, row := range record.Devices {
		device, deviceErr := node.ParseID(row.DeviceID)
		action := memberlifecycle.DeviceAction(row.Action)
		want, known := planned[device]
		if !known {
			want = memberlifecycle.DeviceRevoke
		}
		if deviceErr != nil || seen[device] || action != want || !containsString(removedDeviceState[action], row.State) {
			return memberlifecycle.NetworkRemovalResult{}, memberlifecycle.ErrInvalid
		}
		seen[device] = true
		devices = append(devices, memberlifecycle.RemovedDevice{
			DeviceID: device, NetworkID: removal.Scope.NetworkID(), Hostname: row.Hostname, Action: action,
			State: row.State,
		})
	}
	for device := range planned {
		if !seen[device] {
			return memberlifecycle.NetworkRemovalResult{}, memberlifecycle.ErrInvalid
		}
	}
	advanced, err := advancedNetworks(record.Networks)
	if err != nil || len(advanced) != 1 || advanced[0].NetworkID != removal.Scope.NetworkID() {
		return memberlifecycle.NetworkRemovalResult{}, memberlifecycle.ErrInvalid
	}
	return memberlifecycle.NetworkRemovalResult{
		Before: before, After: after, Devices: devices, HandoversCancelled: *record.HandoversCancelled,
		KeysRevoked: *record.KeysRevoked, RolesRevoked: *record.RolesRevoked,
		Network: memberlifecycle.AdvancedNetwork{
			NetworkID: advanced[0].NetworkID, NetworkRevision: advanced[0].NetworkRevision,
			GroupRevision: advanced[0].GroupRevision,
		},
	}, nil
}

// RemoveNetworkMember authorizes network.member.manage, removes the member
// from the Network and commits it with one event on the Network stream that
// also wakes its map sessions.
func (store *NetworkMemberStore) RemoveNetworkMember(ctx context.Context, removal memberlifecycle.NetworkRemoval) (
	memberlifecycle.NetworkRemovalResult, error) {
	if !removal.IsValid() {
		return memberlifecycle.NetworkRemovalResult{}, memberlifecycle.ErrInvalid
	}
	plan, err := removalPlanJSON(removal.Devices)
	if err != nil {
		return memberlifecycle.NetworkRemovalResult{}, memberlifecycle.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return memberlifecycle.NetworkRemovalResult{}, memberlifecycle.ErrUnavailable
	}
	scope := removal.Scope
	var result memberlifecycle.NetworkRemovalResult
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, removeNetworkMemberSQL, append(sessionQueryArguments(removal.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), removal.MemberID.String(), string(plan),
			changeID.String(), removal.EvaluatedAt)...).Scan(&encoded); err != nil {
			return false, memberLifecycleDatabaseError(err)
		}
		var record networkRemovalRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil {
			return false, memberlifecycle.ErrInvalid
		}
		decoded, err := record.decode(removal)
		if err != nil {
			return false, err
		}
		result = decoded
		event, err := networkMemberRemovedEvent(removal, changeID, result, record.Authority)
		if err != nil {
			return false, err
		}
		if err := appendNetworkMemberEvent(ctx, tx, event); err != nil {
			return false, errors.Join(memberlifecycle.ErrUnavailable, err)
		}
		return true, nil
	})
	if err != nil {
		return memberlifecycle.NetworkRemovalResult{}, err
	}
	return result, nil
}

func networkMemberRemovedEvent(removal memberlifecycle.NetworkRemoval, changeID publicid.ID,
	result memberlifecycle.NetworkRemovalResult, authority catalogAuthority) (catalogEvent, error) {
	networkID := removal.Scope.NetworkID()
	before, err := networkMembershipSemanticHash(networkID, result.Before)
	if err != nil {
		return catalogEvent{}, err
	}
	after, err := networkMembershipSemanticHash(networkID, result.After)
	if err != nil {
		return catalogEvent{}, err
	}
	type deviceOutcome struct {
		DeviceID string `json:"device_id"`
		Action   string `json:"action"`
		State    string `json:"state"`
	}
	devices := make([]deviceOutcome, len(result.Devices))
	for index, device := range result.Devices {
		devices[index] = deviceOutcome{device.DeviceID.String(), string(device.Action), device.State}
	}
	newOwners := map[string]string{}
	for _, plan := range removal.Devices {
		if plan.Action == memberlifecycle.DeviceTransferMember {
			newOwners[plan.DeviceID.String()] = plan.NewOwnerID.String()
		}
	}
	return catalogEvent{
		session: removal.Session, correlationID: removal.CorrelationID, changeID: changeID,
		aggregateKind: "network_membership", aggregateID: removal.MemberID, version: result.After.Version,
		networkVersion: result.Network.NetworkRevision, action: "network.member.removed",
		permission: networkMemberPermission, before: &before, after: after,
		payload: struct {
			NetworkID string           `json:"network_id"`
			SessionID string           `json:"session_id"`
			Change    any              `json:"change"`
			Authority catalogAuthority `json:"authority"`
		}{networkID.String(), removal.Session.ID().String(), struct {
			MemberID           string            `json:"member_principal_id"`
			MembershipID       string            `json:"membership_id"`
			Reason             string            `json:"reason"`
			Devices            []deviceOutcome   `json:"devices"`
			NewOwners          map[string]string `json:"new_owner_principal_ids"`
			HandoversCancelled int               `json:"handovers_cancelled"`
			KeysRevoked        int               `json:"enrollment_keys_revoked"`
			RolesRevoked       int               `json:"roles_revoked"`
		}{removal.MemberID.String(), result.After.MembershipID.String(), removal.Reason, devices, newOwners,
			result.HandoversCancelled, result.KeysRevoked, result.RolesRevoked}, authority},
		// The removal changed the Network's Devices: wake its map sessions.
		outboxClass: "network.revision.advanced",
		outbox: struct {
			NetworkID       string `json:"network_id"`
			Aggregate       string `json:"aggregate_kind"`
			AggregateID     string `json:"aggregate_id"`
			NetworkRevision int64  `json:"network_revision"`
			GroupRevision   int64  `json:"group_revision"`
		}{networkID.String(), "network_membership", removal.MemberID.String(), result.Network.NetworkRevision,
			result.Network.GroupRevision},
	}, nil
}

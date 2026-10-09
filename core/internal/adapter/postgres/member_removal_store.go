package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/meshtransit/meshtransit/core/internal/domain/memberlifecycle"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

const removeWorkspaceMemberSQL = `SELECT mesh_ops.remove_workspace_member_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::JSONB,$13::UUID,$14::TIMESTAMPTZ)::TEXT`

type memberRemovedDeviceRow struct {
	DeviceID  string `json:"device_id"`
	NetworkID string `json:"network_id"`
	Hostname  string `json:"hostname"`
	Action    string `json:"action"`
	State     string `json:"state"`
}

type memberRemovalRecord struct {
	Before             memberLifecycleDocument  `json:"before"`
	After              memberLifecycleDocument  `json:"after"`
	Devices            []memberRemovedDeviceRow `json:"devices"`
	HandoversCancelled *int                     `json:"handovers_cancelled"`
	KeysRevoked        *int                     `json:"keys_revoked"`
	GroupsLeft         *int                     `json:"groups_left"`
	RolesRevoked       *int                     `json:"roles_revoked"`
	SessionsEnded      *int                     `json:"sessions_ended"`
	Networks           []advancedNetworkRow     `json:"networks"`
	Authority          catalogAuthority         `json:"authority"`
}

// removedDeviceState is the only state each action may leave a Device in,
// except that a Device moved to the Workspace keeps an administrator's
// suspension.
var removedDeviceState = map[memberlifecycle.DeviceAction][]string{
	memberlifecycle.DeviceTransferWorkspace: {"active", "suspended"},
	memberlifecycle.DeviceTransferMember:    {"suspended"},
	memberlifecycle.DeviceRevoke:            {"revoked"},
}

func nonNegative(values ...*int) bool {
	for _, value := range values {
		if value == nil || *value < 0 {
			return false
		}
	}
	return true
}

// decode validates the record against the removal and returns the result.
func (record memberRemovalRecord) decode(removal memberlifecycle.Removal) (memberlifecycle.RemovalResult, error) {
	before, err := record.Before.member()
	if err != nil {
		return memberlifecycle.RemovalResult{}, err
	}
	after, err := record.After.member()
	if err != nil || before.PrincipalID != removal.MemberID || after.PrincipalID != removal.MemberID ||
		before.State == "revoked" || after.State != "revoked" || after.Version != before.Version+1 ||
		record.Devices == nil || record.Networks == nil ||
		!nonNegative(record.HandoversCancelled, record.KeysRevoked, record.GroupsLeft, record.RolesRevoked,
			record.SessionsEnded) {
		return memberlifecycle.RemovalResult{}, memberlifecycle.ErrInvalid
	}
	planned := make(map[node.ID]memberlifecycle.DeviceAction, len(removal.Devices))
	for _, plan := range removal.Devices {
		planned[plan.DeviceID] = plan.Action
	}
	devices := make([]memberlifecycle.RemovedDevice, 0, len(record.Devices))
	seen := make(map[node.ID]bool, len(record.Devices))
	for _, row := range record.Devices {
		device, deviceErr := node.ParseID(row.DeviceID)
		networkID, networkErr := network.ParseID(row.NetworkID)
		action := memberlifecycle.DeviceAction(row.Action)
		want, known := planned[device]
		if !known {
			want = memberlifecycle.DeviceRevoke
		}
		if deviceErr != nil || networkErr != nil || seen[device] || action != want ||
			!containsString(removedDeviceState[action], row.State) {
			return memberlifecycle.RemovalResult{}, memberlifecycle.ErrInvalid
		}
		seen[device] = true
		devices = append(devices, memberlifecycle.RemovedDevice{
			DeviceID: device, NetworkID: networkID, Hostname: row.Hostname, Action: action, State: row.State,
		})
	}
	for device := range planned {
		if !seen[device] {
			return memberlifecycle.RemovalResult{}, memberlifecycle.ErrInvalid
		}
	}
	advanced, err := advancedNetworks(record.Networks)
	if err != nil {
		return memberlifecycle.RemovalResult{}, memberlifecycle.ErrInvalid
	}
	networks := make([]memberlifecycle.AdvancedNetwork, 0, len(advanced))
	for _, row := range advanced {
		networks = append(networks, memberlifecycle.AdvancedNetwork{
			NetworkID: row.NetworkID, NetworkRevision: row.NetworkRevision, GroupRevision: row.GroupRevision,
		})
	}
	return memberlifecycle.RemovalResult{
		Before: before, After: after, Devices: devices, HandoversCancelled: *record.HandoversCancelled,
		KeysRevoked: *record.KeysRevoked, GroupsLeft: *record.GroupsLeft, RolesRevoked: *record.RolesRevoked,
		SessionsEnded: *record.SessionsEnded, Networks: networks,
	}, nil
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// removalPlanJSON encodes the plan as remove_workspace_member_v1 reads it.
func removalPlanJSON(plans []memberlifecycle.DevicePlan) ([]byte, error) {
	type planItem struct {
		DeviceID   string `json:"device_id"`
		Action     string `json:"action"`
		NewOwnerID string `json:"new_owner_id,omitempty"`
	}
	items := make([]planItem, len(plans))
	for index, plan := range plans {
		items[index] = planItem{DeviceID: plan.DeviceID.String(), Action: string(plan.Action)}
		if plan.Action == memberlifecycle.DeviceTransferMember {
			items[index].NewOwnerID = plan.NewOwnerID.String()
		}
	}
	return json.Marshal(items)
}

// Remove authorizes member.manage, removes the member and commits it with its
// evidence on the Workspace stream and on every advanced Network's stream.
func (store *MemberLifecycleStore) Remove(ctx context.Context, removal memberlifecycle.Removal) (
	memberlifecycle.RemovalResult, error) {
	if !removal.IsValid() {
		return memberlifecycle.RemovalResult{}, memberlifecycle.ErrInvalid
	}
	plan, err := removalPlanJSON(removal.Devices)
	if err != nil {
		return memberlifecycle.RemovalResult{}, memberlifecycle.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return memberlifecycle.RemovalResult{}, memberlifecycle.ErrUnavailable
	}
	var result memberlifecycle.RemovalResult
	err = store.transact(ctx, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, removeWorkspaceMemberSQL, append(sessionQueryArguments(removal.Session),
			removal.WorkspaceID.String(), removal.MemberID.String(), string(plan), changeID.String(),
			removal.EvaluatedAt)...).Scan(&encoded); err != nil {
			return false, memberLifecycleDatabaseError(err)
		}
		var record memberRemovalRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil {
			return false, memberlifecycle.ErrInvalid
		}
		decoded, err := record.decode(removal)
		if err != nil {
			return false, err
		}
		result = decoded
		event, reason, err := memberRemovalEvent(removal, changeID, result, record.Authority)
		if err != nil {
			return false, err
		}
		if err := appendWorkspaceCatalogEvent(ctx, tx, removal.WorkspaceID, event); err != nil {
			return false, errors.Join(memberlifecycle.ErrUnavailable, err)
		}
		if err := appendNetworkWakeEvents(ctx, tx, identityAdvancedNetworks(result.Networks), event, reason); err != nil {
			return false, errors.Join(memberlifecycle.ErrUnavailable, err)
		}
		return true, nil
	})
	if err != nil {
		return memberlifecycle.RemovalResult{}, err
	}
	return result, nil
}

// memberRemovalEvent builds the Workspace evidence and the reason the Network
// wakeups repeat.
func memberRemovalEvent(removal memberlifecycle.Removal, changeID publicid.ID,
	result memberlifecycle.RemovalResult, authority catalogAuthority) (catalogEvent, any, error) {
	beforeHash, err := memberSemanticHash(result.Before)
	if err != nil {
		return catalogEvent{}, nil, err
	}
	afterHash, err := memberSemanticHash(result.After)
	if err != nil {
		return catalogEvent{}, nil, err
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
	reason := struct {
		MemberID           string            `json:"member_principal_id"`
		Action             string            `json:"action"`
		Reason             string            `json:"reason"`
		Devices            []deviceOutcome   `json:"devices"`
		NewOwners          map[string]string `json:"new_owner_principal_ids"`
		HandoversCancelled int               `json:"handovers_cancelled"`
		KeysRevoked        int               `json:"enrollment_keys_revoked"`
		GroupsLeft         int               `json:"identity_groups_left"`
		RolesRevoked       int               `json:"roles_revoked"`
		SessionsEnded      int               `json:"sessions_ended"`
	}{removal.MemberID.String(), "remove", removal.Reason, devices, newOwners, result.HandoversCancelled,
		result.KeysRevoked, result.GroupsLeft, result.RolesRevoked, result.SessionsEnded}
	event := catalogEvent{
		session: removal.Session, correlationID: removal.CorrelationID, changeID: changeID,
		aggregateKind: "workspace_membership", aggregateID: removal.MemberID, version: result.After.Version,
		action: "member.removed", permission: "member.manage",
		before: &beforeHash, after: afterHash,
		payload: struct {
			WorkspaceID string           `json:"workspace_id"`
			SessionID   string           `json:"session_id"`
			Change      any              `json:"change"`
			Authority   catalogAuthority `json:"authority"`
		}{removal.WorkspaceID.String(), removal.Session.ID().String(), reason, authority},
		outboxClass: "member.removed",
		outbox: struct {
			WorkspaceID string `json:"workspace_id"`
			MemberID    string `json:"member_principal_id"`
			Version     int64  `json:"version"`
		}{removal.WorkspaceID.String(), removal.MemberID.String(), result.After.Version},
	}
	return event, reason, nil
}

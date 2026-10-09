package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const maximumDeviceGroupDocumentBytes = 1 << 20

const listDeviceGroupsSQL = `SELECT mesh_ops.list_device_groups_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TIMESTAMPTZ)::TEXT`

const readDeviceGroupMembersSQL = `SELECT mesh_ops.read_device_group_members_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,NULLIF($13::TEXT,'')::UUID,$14::INTEGER,$15::TIMESTAMPTZ)::TEXT`

const changeDeviceGroupSQL = `SELECT mesh_ops.change_device_group_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TEXT,$13::UUID,$14::BIGINT,$15::TEXT,$16::TEXT,$17::UUID,$18::TIMESTAMPTZ)::TEXT`

const changeDeviceGroupMembersSQL = `SELECT mesh_ops.change_device_group_members_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::BIGINT,$14::JSONB,$15::UUID[],$16::UUID,$17::TIMESTAMPTZ)::TEXT`

const appendDeviceGroupEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'device_group',$7::UUID,$8::BIGINT,$9::BIGINT,$10::UUID,$11::TEXT,$12::TEXT,
 $13::UUID,$14::BYTEA,$15::BYTEA,$16::JSONB,$17::TEXT,$18::JSONB)`

// DeviceGroupStore reads and changes Network Device Groups through the
// runtime pool. Each change commits with its evidence on the Network stream;
// a membership change also wakes map sessions through the revision outbox.
type DeviceGroupStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ devicegroup.Store = (*DeviceGroupStore)(nil)

// NewDeviceGroupStore uses the runtime pool.
func NewDeviceGroupStore(pool *Pool, options AccountSessionOptions) (*DeviceGroupStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, devicegroup.ErrInvalid
	}
	return &DeviceGroupStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func deviceGroupDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return devicegroup.ErrForbidden
		case "P0002":
			return devicegroup.ErrNotFound
		case "40001":
			return devicegroup.ErrVersionConflict
		case "MTD01":
			return devicegroup.ErrIneligibleDevice
		case "MTD02":
			return devicegroup.ErrGroupLimit
		case "MTD03":
			return devicegroup.ErrMemberLimit
		case "MTD04":
			return devicegroup.ErrNameTaken
		case "MTD05":
			return devicegroup.ErrInUse
		case "MTD06":
			return devicegroup.ErrEdgeBudget
		case "22023", "22P02", "23514":
			return devicegroup.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return devicegroup.ErrForbidden
	}
	return errors.Join(devicegroup.ErrUnavailable, err)
}

func (store *DeviceGroupStore) begin(ctx context.Context, scope network.Scope) (accountSessionTransaction, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return nil, devicegroup.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return nil, errors.Join(devicegroup.ErrUnavailable, err)
	}
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return tx, errors.Join(devicegroup.ErrUnavailable, err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
		return tx, deviceGroupDatabaseError(err)
	}
	if workspaceInternal <= 0 || networkInternal <= 0 {
		return tx, devicegroup.ErrForbidden
	}
	return tx, nil
}

func decodeDeviceGroupJSON(encoded []byte, target any) error {
	if len(encoded) == 0 || len(encoded) > maximumDeviceGroupDocumentBytes {
		return devicegroup.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return devicegroup.ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return devicegroup.ErrInvalid
	}
	return nil
}

type deviceGroupDocument struct {
	ID          string    `json:"group_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	MemberCount int       `json:"member_count"`
	RuleCount   int       `json:"rule_count"`
	State       string    `json:"state"`
	Version     int64     `json:"version"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func (document deviceGroupDocument) group(allowDeleted bool) (devicegroup.Group, error) {
	id, err := devicegroup.ParseID(document.ID)
	if err != nil || (document.State != "active" && (!allowDeleted || document.State != "deleted")) {
		return devicegroup.Group{}, devicegroup.ErrInvalid
	}
	group := devicegroup.Group{
		ID: id, Version: document.Version, MemberCount: document.MemberCount, RuleCount: document.RuleCount,
		CreatedAt: document.CreatedAt, UpdatedAt: document.UpdatedAt,
		Definition: devicegroup.Definition{Name: document.Name, Description: document.Description},
	}
	if !group.IsValid() {
		return devicegroup.Group{}, devicegroup.ErrInvalid
	}
	return group, nil
}

// List authorizes device_group.read and returns the active groups.
func (store *DeviceGroupStore) List(ctx context.Context, session accountsession.Session, scope network.Scope,
	at time.Time) (_ devicegroup.Listing, resultErr error) {
	if !session.IsValid() || !scope.IsValid() || at.IsZero() {
		return devicegroup.Listing{}, devicegroup.ErrInvalid
	}
	tx, err := store.begin(ctx, scope)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return devicegroup.Listing{}, err
	}
	var encoded string
	if err := tx.QueryRow(ctx, listDeviceGroupsSQL, append(sessionQueryArguments(session),
		scope.WorkspaceID().String(), scope.NetworkID().String(), at)...).Scan(&encoded); err != nil {
		return devicegroup.Listing{}, deviceGroupDatabaseError(err)
	}
	var envelope struct {
		Groups           []deviceGroupDocument `json:"groups"`
		CanManage        bool                  `json:"can_manage"`
		CanManageMembers bool                  `json:"can_manage_members"`
	}
	if err := decodeDeviceGroupJSON([]byte(encoded), &envelope); err != nil || envelope.Groups == nil ||
		len(envelope.Groups) > devicegroup.MaximumGroups {
		return devicegroup.Listing{}, devicegroup.ErrInvalid
	}
	listing := devicegroup.Listing{
		Groups:    make([]devicegroup.Group, 0, len(envelope.Groups)),
		CanManage: envelope.CanManage, CanManageMembers: envelope.CanManageMembers,
	}
	for _, document := range envelope.Groups {
		group, err := document.group(false)
		if err != nil {
			return devicegroup.Listing{}, err
		}
		listing.Groups = append(listing.Groups, group)
	}
	return listing, nil
}

// Members authorizes device_group.read and returns one page of members.
func (store *DeviceGroupStore) Members(ctx context.Context, session accountsession.Session, scope network.Scope,
	group devicegroup.ID, after node.ID, limit int, at time.Time) (_ devicegroup.MemberPage, resultErr error) {
	if !session.IsValid() || !scope.IsValid() || !group.IsValid() || limit < 1 ||
		limit > devicegroup.MaximumMemberPage || at.IsZero() {
		return devicegroup.MemberPage{}, devicegroup.ErrInvalid
	}
	tx, err := store.begin(ctx, scope)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return devicegroup.MemberPage{}, err
	}
	afterText := ""
	if after.IsValid() {
		afterText = after.String()
	}
	var encoded string
	if err := tx.QueryRow(ctx, readDeviceGroupMembersSQL, append(sessionQueryArguments(session),
		scope.WorkspaceID().String(), scope.NetworkID().String(), group.String(), afterText, limit, at)...).
		Scan(&encoded); err != nil {
		return devicegroup.MemberPage{}, deviceGroupDatabaseError(err)
	}
	var envelope struct {
		Group   deviceGroupDocument `json:"group"`
		Members []struct {
			DeviceID string    `json:"device_id"`
			Name     string    `json:"name"`
			Active   bool      `json:"active"`
			AddedAt  time.Time `json:"added_at"`
		} `json:"members"`
		HasMore bool `json:"has_more"`
	}
	if err := decodeDeviceGroupJSON([]byte(encoded), &envelope); err != nil || envelope.Members == nil ||
		len(envelope.Members) > limit {
		return devicegroup.MemberPage{}, devicegroup.ErrInvalid
	}
	stored, err := envelope.Group.group(false)
	if err != nil || stored.ID != group {
		return devicegroup.MemberPage{}, devicegroup.ErrInvalid
	}
	page := devicegroup.MemberPage{Group: stored, HasMore: envelope.HasMore,
		Members: make([]devicegroup.Member, 0, len(envelope.Members))}
	for _, item := range envelope.Members {
		id, err := node.ParseID(item.DeviceID)
		if err != nil || item.AddedAt.IsZero() {
			return devicegroup.MemberPage{}, devicegroup.ErrInvalid
		}
		page.Members = append(page.Members, devicegroup.Member{
			DeviceID: id, Name: item.Name, Active: item.Active, AddedAt: item.AddedAt,
		})
	}
	return page, nil
}

type deviceGroupChangeRecord struct {
	Group            deviceGroupDocument  `json:"group"`
	Previous         *deviceGroupDocument `json:"previous"`
	Added            *int                 `json:"added"`
	Removed          *int                 `json:"removed"`
	Changed          *bool                `json:"changed"`
	MemberHashBefore *string              `json:"member_hash_before"`
	MemberHashAfter  string               `json:"member_hash_after"`
	NetworkRevision  int64                `json:"network_revision"`
	GroupRevision    *int64               `json:"group_revision"`
	RoleBindingID    *string              `json:"role_binding_id"`
}

func memberHash(text *string) ([]byte, error) {
	if text == nil {
		return nil, nil
	}
	value, err := hex.DecodeString(*text)
	if err != nil || len(value) != sha256.Size {
		return nil, devicegroup.ErrInvalid
	}
	return value, nil
}

// deviceGroupSemanticHash commits to what a group selects: its identity,
// name, state and exact member set.
func deviceGroupSemanticHash(document deviceGroupDocument, members []byte) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		GroupID    string `json:"group_id"`
		Name       string `json:"name"`
		State      string `json:"state"`
		MemberHash string `json:"member_set_sha256"`
	}{document.ID, document.Name, document.State, hex.EncodeToString(members)})
	return sha256.Sum256(encoded), err
}

// Change authorizes device_group.manage, applies the definition change and
// commits it with evidence on the Network stream.
func (store *DeviceGroupStore) Change(ctx context.Context, change devicegroup.Change) (_ devicegroup.Result,
	resultErr error) {
	if !change.Session.IsValid() || !change.Scope.IsValid() || !change.GroupID.IsValid() ||
		!change.CorrelationID.IsValid() || change.EvaluatedAt.IsZero() {
		return devicegroup.Result{}, devicegroup.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return devicegroup.Result{}, devicegroup.ErrUnavailable
	}
	tx, err := store.begin(ctx, change.Scope)
	committed := false
	if tx != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
			}
		}()
	}
	if err != nil {
		return devicegroup.Result{}, err
	}
	var expected any
	if change.Operation != devicegroup.OperationCreate {
		expected = change.ExpectedVersion
	}
	var name, description any
	if change.Operation != devicegroup.OperationDelete {
		name, description = change.Definition.Name, change.Definition.Description
	}
	var encoded string
	if err := tx.QueryRow(ctx, changeDeviceGroupSQL, append(sessionQueryArguments(change.Session),
		change.Scope.WorkspaceID().String(), change.Scope.NetworkID().String(), string(change.Operation),
		change.GroupID.String(), expected, name, description, changeID.String(), change.EvaluatedAt)...).
		Scan(&encoded); err != nil {
		return devicegroup.Result{}, deviceGroupDatabaseError(err)
	}
	var record deviceGroupChangeRecord
	if err := decodeDeviceGroupJSON([]byte(encoded), &record); err != nil || record.NetworkRevision <= 0 {
		return devicegroup.Result{}, devicegroup.ErrInvalid
	}
	deleted := change.Operation == devicegroup.OperationDelete
	saved, err := record.Group.group(deleted)
	if err != nil || saved.ID != change.GroupID || (record.Previous == nil) != (change.Operation == devicegroup.OperationCreate) {
		return devicegroup.Result{}, devicegroup.ErrInvalid
	}
	result := devicegroup.Result{Group: saved, Deleted: deleted}
	if record.Previous != nil {
		previous, err := record.Previous.group(false)
		if err != nil || previous.Version != change.ExpectedVersion {
			return devicegroup.Result{}, devicegroup.ErrInvalid
		}
		result.Previous = &previous
	}
	if err := appendDeviceGroupEvidence(ctx, tx, change.Session, change.Scope, change.CorrelationID, changeID,
		record, deviceGroupAction(change.Operation), "device_group.manage", nil, nil); err != nil {
		return devicegroup.Result{}, errors.Join(devicegroup.ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return devicegroup.Result{}, errors.Join(devicegroup.ErrUnavailable, err)
	}
	committed = true
	return result, nil
}

func deviceGroupAction(operation devicegroup.Operation) string {
	switch operation {
	case devicegroup.OperationCreate:
		return "device_group.created"
	case devicegroup.OperationUpdate:
		return "device_group.updated"
	default:
		return "device_group.deleted"
	}
}

// ChangeMembers authorizes device_group.members.manage and applies the
// membership change. When the set changed, the evidence also carries the
// revision wakeup so maps rebuild with the new members.
func (store *DeviceGroupStore) ChangeMembers(ctx context.Context, change devicegroup.MembershipChange) (
	_ devicegroup.MembershipResult, resultErr error) {
	if !change.Session.IsValid() || !change.Scope.IsValid() || !change.GroupID.IsValid() ||
		change.ExpectedVersion <= 0 || len(change.Add) != len(change.AddMemberIDs) ||
		!change.CorrelationID.IsValid() || change.EvaluatedAt.IsZero() {
		return devicegroup.MembershipResult{}, devicegroup.ErrInvalid
	}
	type addition struct {
		DeviceID string `json:"device_id"`
		MemberID string `json:"member_id"`
	}
	additions := make([]addition, len(change.Add))
	added := make([]string, len(change.Add))
	for index, id := range change.Add {
		additions[index] = addition{DeviceID: id.String(), MemberID: change.AddMemberIDs[index].String()}
		added[index] = id.String()
	}
	removed := make([]string, len(change.Remove))
	for index, id := range change.Remove {
		removed[index] = id.String()
	}
	addJSON, err := json.Marshal(additions)
	if err != nil {
		return devicegroup.MembershipResult{}, devicegroup.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return devicegroup.MembershipResult{}, devicegroup.ErrUnavailable
	}
	tx, err := store.begin(ctx, change.Scope)
	committed := false
	if tx != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
			}
		}()
	}
	if err != nil {
		return devicegroup.MembershipResult{}, err
	}
	var encoded string
	if err := tx.QueryRow(ctx, changeDeviceGroupMembersSQL, append(sessionQueryArguments(change.Session),
		change.Scope.WorkspaceID().String(), change.Scope.NetworkID().String(), change.GroupID.String(),
		change.ExpectedVersion, addJSON, removed, changeID.String(), change.EvaluatedAt)...).Scan(&encoded); err != nil {
		return devicegroup.MembershipResult{}, deviceGroupDatabaseError(err)
	}
	var record deviceGroupChangeRecord
	if err := decodeDeviceGroupJSON([]byte(encoded), &record); err != nil || record.Changed == nil ||
		record.Added == nil || record.Removed == nil || record.Previous == nil || record.NetworkRevision <= 0 ||
		record.GroupRevision == nil {
		return devicegroup.MembershipResult{}, devicegroup.ErrInvalid
	}
	saved, err := record.Group.group(false)
	if err != nil || saved.ID != change.GroupID || *record.Changed != (*record.Added+*record.Removed > 0) {
		return devicegroup.MembershipResult{}, devicegroup.ErrInvalid
	}
	result := devicegroup.MembershipResult{
		Group: saved, Added: *record.Added, Removed: *record.Removed,
		AccessAffecting: *record.Changed && saved.RuleCount > 0,
	}
	if !*record.Changed {
		// Nothing changed: no evidence, no wakeup; the transaction rolls back.
		return result, nil
	}
	if err := appendDeviceGroupEvidence(ctx, tx, change.Session, change.Scope, change.CorrelationID, changeID,
		record, "device_group.members_changed", "device_group.members.manage", added, removed); err != nil {
		return devicegroup.MembershipResult{}, errors.Join(devicegroup.ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return devicegroup.MembershipResult{}, errors.Join(devicegroup.ErrUnavailable, err)
	}
	committed = true
	return result, nil
}

func appendDeviceGroupEvidence(ctx context.Context, tx accountSessionTransaction, session accountsession.Session,
	scope network.Scope, correlationID, changeID publicid.ID, record deviceGroupChangeRecord,
	action, permission string, added, removed []string) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_network_stream_head()`).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return devicegroup.ErrInvalid
	}
	membersBefore, err := memberHash(record.MemberHashBefore)
	if err != nil {
		return err
	}
	membersAfter, err := memberHash(&record.MemberHashAfter)
	if err != nil {
		return err
	}
	var before [32]byte
	var beforeArgument any
	if record.Previous != nil {
		if before, err = deviceGroupSemanticHash(*record.Previous, membersBefore); err != nil {
			return err
		}
		beforeArgument = before[:]
	}
	after, err := deviceGroupSemanticHash(record.Group, membersAfter)
	if err != nil {
		return err
	}
	binding := ""
	if record.RoleBindingID != nil {
		binding = *record.RoleBindingID
	}
	networkID := scope.NetworkID().String()
	payload, err := json.Marshal(struct {
		NetworkID        string   `json:"network_id"`
		SessionID        string   `json:"session_id"`
		RoleBindingID    string   `json:"role_binding_id,omitempty"`
		GroupID          string   `json:"group_id"`
		Name             string   `json:"display_name"`
		PreviousName     string   `json:"previous_display_name,omitempty"`
		MemberCount      int      `json:"member_count"`
		RuleCount        int      `json:"rule_count"`
		AddedDevices     []string `json:"added_device_ids,omitempty"`
		RemovedDevices   []string `json:"removed_device_ids,omitempty"`
		AccessAffecting  bool     `json:"access_affecting"`
		MemberHashBefore string   `json:"member_set_sha256_before,omitempty"`
		MemberHashAfter  string   `json:"member_set_sha256"`
	}{
		NetworkID: networkID, SessionID: session.ID().String(), RoleBindingID: binding,
		GroupID: record.Group.ID, Name: record.Group.Name, PreviousName: previousName(record),
		MemberCount: record.Group.MemberCount, RuleCount: record.Group.RuleCount,
		AddedDevices: added, RemovedDevices: removed,
		AccessAffecting:  record.Group.RuleCount > 0 && len(added)+len(removed) > 0,
		MemberHashBefore: hex.EncodeToString(membersBefore), MemberHashAfter: hex.EncodeToString(membersAfter),
	})
	if err != nil {
		return err
	}
	outboxClass := "device_group.changed"
	outboxValue := struct {
		NetworkID       string `json:"network_id"`
		GroupID         string `json:"group_id"`
		Version         int64  `json:"version"`
		NetworkRevision int64  `json:"network_revision"`
		GroupRevision   int64  `json:"group_revision,omitempty"`
	}{networkID, record.Group.ID, record.Group.Version, record.NetworkRevision, 0}
	if record.GroupRevision != nil {
		// A membership change advanced the Network revision: wake map sessions.
		outboxClass = "network.revision.advanced"
		outboxValue.GroupRevision = *record.GroupRevision
	}
	outbox, err := json.Marshal(outboxValue)
	if err != nil {
		return err
	}
	eventID, err := publicid.New()
	if err != nil {
		return err
	}
	outboxID, err := publicid.New()
	if err != nil {
		return err
	}
	groupID, err := publicid.Parse(record.Group.ID)
	if err != nil {
		return devicegroup.ErrInvalid
	}
	var previousHash [32]byte
	copy(previousHash[:], previous)
	principal := publicid.ID(session.PrincipalID())
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: eventID, ChangeID: changeID,
		AggregateKind: "device_group", AggregateID: groupID, AggregateVersion: record.Group.Version,
		NetworkRevision: record.NetworkRevision, ActorPrincipalID: principal, Action: action,
		Permission: permission, CorrelationID: correlationID,
		BeforeSemanticHash: before, AfterSemanticHash: after, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: outboxClass, OutboxPayloadHash: sha256.Sum256(outbox),
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendDeviceGroupEvidenceSQL, streamID, eventID.String(), outboxID.String(), sequence,
		previousHash[:], eventHash[:], record.Group.ID, record.Group.Version, record.NetworkRevision,
		principal.String(), action, permission, correlationID.String(), beforeArgument, after[:], payload,
		outboxClass, outbox).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return devicegroup.ErrInvalid
	}
	return nil
}

func previousName(record deviceGroupChangeRecord) string {
	if record.Previous == nil || record.Previous.Name == record.Group.Name {
		return ""
	}
	return record.Previous.Name
}

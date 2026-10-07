package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identitygroup"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const listIdentityGroupsSQL = `SELECT mesh_ops.list_identity_groups_v1(` + sessionArguments + `,
 $10::UUID,$11::TIMESTAMPTZ)::TEXT`

const readIdentityGroupMembersSQL = `SELECT mesh_ops.read_identity_group_members_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,NULLIF($12::TEXT,'')::UUID,$13::INTEGER,$14::TIMESTAMPTZ)::TEXT`

const changeIdentityGroupSQL = `SELECT mesh_ops.change_identity_group_v1(` + sessionArguments + `,
 $10::UUID,$11::TEXT,$12::UUID,$13::BIGINT,$14::TEXT,$15::TEXT,$16::UUID,$17::TIMESTAMPTZ)::TEXT`

const changeIdentityGroupMembersSQL = `SELECT mesh_ops.change_identity_group_members_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::BIGINT,$13::JSONB,$14::UUID[],$15::UUID,$16::TIMESTAMPTZ)::TEXT`

// IdentityGroupStore reads and changes Workspace Identity Groups through the
// runtime pool. Each change commits with evidence on the Workspace stream; a
// membership change that rebuilds Networks also records the wakeup on each
// Network's stream.
type IdentityGroupStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ identitygroup.Store = (*IdentityGroupStore)(nil)

// NewIdentityGroupStore uses the runtime pool.
func NewIdentityGroupStore(pool *Pool, options AccountSessionOptions) (*IdentityGroupStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, identitygroup.ErrInvalid
	}
	return &IdentityGroupStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func identityGroupDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return identitygroup.ErrForbidden
		case "P0002":
			return identitygroup.ErrNotFound
		case "40001":
			return identitygroup.ErrVersionConflict
		case "MTI01":
			return identitygroup.ErrIneligibleMember
		case "MTI02":
			return identitygroup.ErrGroupLimit
		case "MTI03":
			return identitygroup.ErrMemberLimit
		case "MTI04":
			return identitygroup.ErrNameTaken
		case "MTI05":
			return identitygroup.ErrInUse
		case "MTD06":
			return identitygroup.ErrEdgeBudget
		case "22023", "22P02", "23514":
			return identitygroup.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return identitygroup.ErrForbidden
	}
	return errors.Join(identitygroup.ErrUnavailable, err)
}

func (store *IdentityGroupStore) begin(ctx context.Context) (accountSessionTransaction, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return nil, identitygroup.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return nil, errors.Join(identitygroup.ErrUnavailable, err)
	}
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return tx, errors.Join(identitygroup.ErrUnavailable, err)
	}
	return tx, nil
}

type identityGroupDocument struct {
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

func (document identityGroupDocument) group(allowDeleted bool) (identitygroup.Group, error) {
	id, err := identitygroup.ParseID(document.ID)
	if err != nil || (document.State != "active" && (!allowDeleted || document.State != "deleted")) {
		return identitygroup.Group{}, identitygroup.ErrInvalid
	}
	group := identitygroup.Group{
		ID: id, Version: document.Version, MemberCount: document.MemberCount, RuleCount: document.RuleCount,
		CreatedAt: document.CreatedAt, UpdatedAt: document.UpdatedAt,
		Definition: identitygroup.Definition{Name: document.Name, Description: document.Description},
	}
	if !group.IsValid() {
		return identitygroup.Group{}, identitygroup.ErrInvalid
	}
	return group, nil
}

// List authorizes identity_group.read and returns the active groups.
func (store *IdentityGroupStore) List(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	at time.Time) (_ identitygroup.Listing, resultErr error) {
	if !session.IsValid() || !workspaceID.IsValid() || at.IsZero() {
		return identitygroup.Listing{}, identitygroup.ErrInvalid
	}
	tx, err := store.begin(ctx)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return identitygroup.Listing{}, err
	}
	var encoded string
	if err := tx.QueryRow(ctx, listIdentityGroupsSQL, append(sessionQueryArguments(session),
		workspaceID.String(), at)...).Scan(&encoded); err != nil {
		return identitygroup.Listing{}, identityGroupDatabaseError(err)
	}
	var envelope struct {
		Groups    []identityGroupDocument `json:"groups"`
		CanManage bool                    `json:"can_manage"`
	}
	if err := decodeIdentityCatalogJSON([]byte(encoded), &envelope); err != nil || envelope.Groups == nil ||
		len(envelope.Groups) > identitygroup.MaximumGroups {
		return identitygroup.Listing{}, identitygroup.ErrInvalid
	}
	listing := identitygroup.Listing{Groups: make([]identitygroup.Group, 0, len(envelope.Groups)),
		CanManage: envelope.CanManage}
	for _, document := range envelope.Groups {
		group, err := document.group(false)
		if err != nil {
			return identitygroup.Listing{}, err
		}
		listing.Groups = append(listing.Groups, group)
	}
	return listing, nil
}

// Members authorizes identity_group.read and returns one page of members.
func (store *IdentityGroupStore) Members(ctx context.Context, session accountsession.Session,
	workspaceID workspace.ID, group identitygroup.ID, after publicid.ID, limit int,
	at time.Time) (_ identitygroup.MemberPage, resultErr error) {
	if !session.IsValid() || !workspaceID.IsValid() || !group.IsValid() || limit < 1 ||
		limit > identitygroup.MaximumMemberPage || at.IsZero() {
		return identitygroup.MemberPage{}, identitygroup.ErrInvalid
	}
	tx, err := store.begin(ctx)
	if tx != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	}
	if err != nil {
		return identitygroup.MemberPage{}, err
	}
	afterText := ""
	if after.IsValid() {
		afterText = after.String()
	}
	var encoded string
	if err := tx.QueryRow(ctx, readIdentityGroupMembersSQL, append(sessionQueryArguments(session),
		workspaceID.String(), group.String(), afterText, limit, at)...).Scan(&encoded); err != nil {
		return identitygroup.MemberPage{}, identityGroupDatabaseError(err)
	}
	var envelope struct {
		Group   identityGroupDocument `json:"group"`
		Members []struct {
			PrincipalID string    `json:"principal_id"`
			DisplayName string    `json:"display_name"`
			Active      bool      `json:"active"`
			AddedAt     time.Time `json:"added_at"`
		} `json:"members"`
		HasMore bool `json:"has_more"`
	}
	if err := decodeIdentityCatalogJSON([]byte(encoded), &envelope); err != nil || envelope.Members == nil ||
		len(envelope.Members) > limit {
		return identitygroup.MemberPage{}, identitygroup.ErrInvalid
	}
	stored, err := envelope.Group.group(false)
	if err != nil || stored.ID != group {
		return identitygroup.MemberPage{}, identitygroup.ErrInvalid
	}
	page := identitygroup.MemberPage{Group: stored, HasMore: envelope.HasMore,
		Members: make([]identitygroup.Member, 0, len(envelope.Members))}
	for _, item := range envelope.Members {
		id, err := publicid.Parse(item.PrincipalID)
		if err != nil || item.AddedAt.IsZero() || !identitygroup.PlainText(item.DisplayName) {
			return identitygroup.MemberPage{}, identitygroup.ErrInvalid
		}
		page.Members = append(page.Members, identitygroup.Member{
			PrincipalID: id, DisplayName: item.DisplayName, Active: item.Active, AddedAt: item.AddedAt,
		})
	}
	return page, nil
}

type identityGroupChangeRecord struct {
	Group            identityGroupDocument  `json:"group"`
	Previous         *identityGroupDocument `json:"previous"`
	Added            *int                   `json:"added"`
	Removed          *int                   `json:"removed"`
	Changed          *bool                  `json:"changed"`
	MemberHashBefore *string                `json:"member_hash_before"`
	MemberHashAfter  string                 `json:"member_hash_after"`
	Networks         []advancedNetworkRow   `json:"networks"`
	Authority        catalogAuthority       `json:"authority"`
}

type advancedNetworkRow struct {
	NetworkID       string `json:"network_id"`
	NetworkRevision int64  `json:"network_revision"`
	GroupRevision   int64  `json:"group_revision"`
}

func advancedNetworks(rows []advancedNetworkRow) ([]identitygroup.AdvancedNetwork, error) {
	networks := make([]identitygroup.AdvancedNetwork, 0, len(rows))
	for _, row := range rows {
		id, err := network.ParseID(row.NetworkID)
		if err != nil || id.String() != row.NetworkID || row.NetworkRevision <= 0 || row.GroupRevision <= 0 {
			return nil, errIdentityCatalogEvidence
		}
		networks = append(networks, identitygroup.AdvancedNetwork{
			NetworkID: id, NetworkRevision: row.NetworkRevision, GroupRevision: row.GroupRevision,
		})
	}
	return networks, nil
}

func setHash(text *string) ([]byte, error) {
	if text == nil {
		return nil, nil
	}
	value, err := hex.DecodeString(*text)
	if err != nil || len(value) != sha256.Size {
		return nil, errIdentityCatalogEvidence
	}
	return value, nil
}

// identityGroupSemanticHash commits to what a group selects: its identity,
// name, state and exact member set.
func identityGroupSemanticHash(document identityGroupDocument, members []byte) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		GroupID    string `json:"group_id"`
		Name       string `json:"name"`
		State      string `json:"state"`
		MemberHash string `json:"member_set_sha256"`
	}{document.ID, document.Name, document.State, hex.EncodeToString(members)})
	return sha256.Sum256(encoded), err
}

func (store *IdentityGroupStore) transact(ctx context.Context,
	run func(tx accountSessionTransaction) (bool, error)) (resultErr error) {
	tx, err := store.begin(ctx)
	committed := false
	if tx != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
			}
		}()
	}
	if err != nil {
		return err
	}
	commit, err := run(tx)
	if err != nil || !commit {
		return err
	}
	committed = true
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(identitygroup.ErrUnavailable, err)
	}
	return nil
}

// Change authorizes identity_group.manage, applies the definition change and
// commits it with evidence on the Workspace stream.
func (store *IdentityGroupStore) Change(ctx context.Context, change identitygroup.Change) (
	identitygroup.Result, error) {
	if !change.Session.IsValid() || !change.WorkspaceID.IsValid() || !change.GroupID.IsValid() ||
		!change.CorrelationID.IsValid() || change.EvaluatedAt.IsZero() {
		return identitygroup.Result{}, identitygroup.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return identitygroup.Result{}, identitygroup.ErrUnavailable
	}
	var expected, name, description any
	if change.Operation != identitygroup.OperationCreate {
		expected = change.ExpectedVersion
	}
	if change.Operation != identitygroup.OperationDelete {
		name, description = change.Definition.Name, change.Definition.Description
	}
	var result identitygroup.Result
	err = store.transact(ctx, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, changeIdentityGroupSQL, append(sessionQueryArguments(change.Session),
			change.WorkspaceID.String(), string(change.Operation), change.GroupID.String(), expected, name,
			description, changeID.String(), change.EvaluatedAt)...).Scan(&encoded); err != nil {
			return false, identityGroupDatabaseError(err)
		}
		var record identityGroupChangeRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil {
			return false, identitygroup.ErrInvalid
		}
		deleted := change.Operation == identitygroup.OperationDelete
		saved, err := record.Group.group(deleted)
		if err != nil || saved.ID != change.GroupID ||
			(record.Previous == nil) != (change.Operation == identitygroup.OperationCreate) {
			return false, identitygroup.ErrInvalid
		}
		result = identitygroup.Result{Group: saved, Deleted: deleted}
		event := catalogEvent{
			session: change.Session, correlationID: change.CorrelationID, changeID: changeID,
			aggregateKind: "identity_group", aggregateID: publicid.ID(saved.ID), version: saved.Version,
			action: "identity_group." + map[identitygroup.Operation]string{
				identitygroup.OperationCreate: "created", identitygroup.OperationUpdate: "updated",
				identitygroup.OperationDelete: "deleted",
			}[change.Operation],
			permission: "identity_group.manage",
		}
		if record.Previous != nil {
			previous, err := record.Previous.group(false)
			if err != nil || previous.Version != change.ExpectedVersion {
				return false, identitygroup.ErrInvalid
			}
			result.Previous = &previous
			before, err := setHash(record.MemberHashBefore)
			if err != nil {
				return false, err
			}
			hash, err := identityGroupSemanticHash(*record.Previous, before)
			if err != nil {
				return false, err
			}
			event.before = &hash
		}
		after, err := setHash(&record.MemberHashAfter)
		if err != nil {
			return false, err
		}
		if event.after, err = identityGroupSemanticHash(record.Group, after); err != nil {
			return false, err
		}
		previousName := ""
		if result.Previous != nil && result.Previous.Name != saved.Name {
			previousName = result.Previous.Name
		}
		event.payload = struct {
			WorkspaceID  string           `json:"workspace_id"`
			SessionID    string           `json:"session_id"`
			GroupID      string           `json:"group_id"`
			Name         string           `json:"display_name"`
			PreviousName string           `json:"previous_display_name,omitempty"`
			MemberCount  int              `json:"member_count"`
			Authority    catalogAuthority `json:"authority"`
		}{change.WorkspaceID.String(), change.Session.ID().String(), saved.ID.String(), saved.Name, previousName,
			saved.MemberCount, record.Authority}
		event.outboxClass = event.action
		event.outbox = struct {
			WorkspaceID string `json:"workspace_id"`
			GroupID     string `json:"group_id"`
			Version     int64  `json:"version"`
		}{change.WorkspaceID.String(), saved.ID.String(), saved.Version}
		if err := appendWorkspaceCatalogEvent(ctx, tx, change.WorkspaceID, event); err != nil {
			return false, errors.Join(identitygroup.ErrUnavailable, err)
		}
		return true, nil
	})
	if err != nil {
		return identitygroup.Result{}, err
	}
	return result, nil
}

// ChangeMembers authorizes identity_group.manage and applies the membership
// change. Evidence goes on the Workspace stream, and on the stream of each
// Network the change rebuilt, with its revision wakeup.
func (store *IdentityGroupStore) ChangeMembers(ctx context.Context, change identitygroup.MembershipChange) (
	identitygroup.MembershipResult, error) {
	if !change.Session.IsValid() || !change.WorkspaceID.IsValid() || !change.GroupID.IsValid() ||
		change.ExpectedVersion <= 0 || len(change.Add) != len(change.AddMemberIDs) ||
		!change.CorrelationID.IsValid() || change.EvaluatedAt.IsZero() {
		return identitygroup.MembershipResult{}, identitygroup.ErrInvalid
	}
	type addition struct {
		PrincipalID string `json:"principal_id"`
		MemberID    string `json:"member_id"`
	}
	additions := make([]addition, len(change.Add))
	added := make([]string, len(change.Add))
	for index, id := range change.Add {
		additions[index] = addition{PrincipalID: id.String(), MemberID: change.AddMemberIDs[index].String()}
		added[index] = id.String()
	}
	removed := make([]string, len(change.Remove))
	for index, id := range change.Remove {
		removed[index] = id.String()
	}
	addJSON, err := json.Marshal(additions)
	if err != nil {
		return identitygroup.MembershipResult{}, identitygroup.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return identitygroup.MembershipResult{}, identitygroup.ErrUnavailable
	}
	var result identitygroup.MembershipResult
	err = store.transact(ctx, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, changeIdentityGroupMembersSQL, append(sessionQueryArguments(change.Session),
			change.WorkspaceID.String(), change.GroupID.String(), change.ExpectedVersion, addJSON, removed,
			changeID.String(), change.EvaluatedAt)...).Scan(&encoded); err != nil {
			return false, identityGroupDatabaseError(err)
		}
		var record identityGroupChangeRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil || record.Changed == nil ||
			record.Added == nil || record.Removed == nil || record.Previous == nil || record.Networks == nil {
			return false, identitygroup.ErrInvalid
		}
		saved, err := record.Group.group(false)
		if err != nil || saved.ID != change.GroupID || *record.Changed != (*record.Added+*record.Removed > 0) {
			return false, identitygroup.ErrInvalid
		}
		networks, err := advancedNetworks(record.Networks)
		if err != nil || (!*record.Changed && len(networks) > 0) {
			return false, identitygroup.ErrInvalid
		}
		result = identitygroup.MembershipResult{
			Group: saved, Added: *record.Added, Removed: *record.Removed, Networks: networks,
		}
		if !*record.Changed {
			// Nothing changed: no evidence, no wakeup; the transaction rolls back.
			return false, nil
		}
		before, err := setHash(record.MemberHashBefore)
		if err != nil {
			return false, err
		}
		after, err := setHash(&record.MemberHashAfter)
		if err != nil {
			return false, err
		}
		beforeHash, err := identityGroupSemanticHash(*record.Previous, before)
		if err != nil {
			return false, err
		}
		afterHash, err := identityGroupSemanticHash(record.Group, after)
		if err != nil {
			return false, err
		}
		reason := struct {
			GroupID          string   `json:"group_id"`
			Name             string   `json:"display_name"`
			AddedPrincipals  []string `json:"added_principal_ids,omitempty"`
			RemovedPrincipal []string `json:"removed_principal_ids,omitempty"`
			MemberHashBefore string   `json:"member_set_sha256_before"`
			MemberHashAfter  string   `json:"member_set_sha256"`
		}{saved.ID.String(), saved.Name, added, removed, hex.EncodeToString(before), hex.EncodeToString(after)}
		event := catalogEvent{
			session: change.Session, correlationID: change.CorrelationID, changeID: changeID,
			aggregateKind: "identity_group", aggregateID: publicid.ID(saved.ID), version: saved.Version,
			action: "identity_group.members_changed", permission: "identity_group.manage",
			before: &beforeHash, after: afterHash,
			payload: struct {
				WorkspaceID     string           `json:"workspace_id"`
				SessionID       string           `json:"session_id"`
				Change          any              `json:"change"`
				MemberCount     int              `json:"member_count"`
				RuleCount       int              `json:"rule_count"`
				AccessAffecting bool             `json:"access_affecting"`
				Authority       catalogAuthority `json:"authority"`
			}{change.WorkspaceID.String(), change.Session.ID().String(), reason, saved.MemberCount, saved.RuleCount,
				result.AccessAffecting(), record.Authority},
			outboxClass: "identity_group.members_changed",
			outbox: struct {
				WorkspaceID string `json:"workspace_id"`
				GroupID     string `json:"group_id"`
				Version     int64  `json:"version"`
			}{change.WorkspaceID.String(), saved.ID.String(), saved.Version},
		}
		if err := appendWorkspaceCatalogEvent(ctx, tx, change.WorkspaceID, event); err != nil {
			return false, errors.Join(identitygroup.ErrUnavailable, err)
		}
		if err := appendNetworkWakeEvents(ctx, tx, networks, event, reason); err != nil {
			return false, errors.Join(identitygroup.ErrUnavailable, err)
		}
		return true, nil
	})
	if err != nil {
		return identitygroup.MembershipResult{}, err
	}
	return result, nil
}

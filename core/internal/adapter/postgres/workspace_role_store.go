package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/domain/workspace/roles"
)

// WorkspaceRoleStore reads Workspace members and commits built-in role
// assignments through the schema 96 entry points, which own authority, the
// delegation ceiling and the self-change rule.
type WorkspaceRoleStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

// NewWorkspaceRoleStore validates a runtime pool and bounded database waits.
func NewWorkspaceRoleStore(pool *Pool, options AccountSessionOptions) (*WorkspaceRoleStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil || !validAccountSessionOptions(options) {
		return nil, roles.ErrInvalid
	}
	// The rename handle is a plain read-committed read-write transaction.
	return &WorkspaceRoleStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

const sessionArguments = `$1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT`

const listWorkspaceMembersSQL = `SELECT mesh_ops.list_workspace_members_v1(` + sessionArguments + `,$10::UUID)::TEXT`

const assignWorkspaceRoleSQL = `SELECT assignment_public_id::TEXT, assignment_version, assignment_created_at, replayed,
 COALESCE(actor_binding_public_id::TEXT,''), COALESCE(actor_role_public_id::TEXT,''),
 actor_binding_generation, actor_membership_generation, actor_owner_generation
FROM mesh_ops.assign_workspace_role_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TEXT,$14::UUID,$15::TIMESTAMPTZ,$16::UUID)`

const revokeWorkspaceRoleSQL = `SELECT assignment_public_id::TEXT, assignment_version, assignment_role_key,
 target_principal_public_id::TEXT, replayed,
 COALESCE(actor_binding_public_id::TEXT,''), COALESCE(actor_role_public_id::TEXT,''),
 actor_binding_generation, actor_membership_generation, actor_owner_generation
FROM mesh_ops.revoke_workspace_role_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::BIGINT,$13::UUID)`

const appendWorkspaceRoleEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'workspace_role_assignment',$7::UUID,$8::BIGINT,NULL::BIGINT,$9::UUID,$10::TEXT,'role_binding.manage',
 $11::UUID,$12::BYTEA,$13::BYTEA,$14::JSONB,$10::TEXT,$15::JSONB)`

func sessionQueryArguments(session accountsession.Session) []any {
	return []any{session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch()}
}

func (store *WorkspaceRoleStore) begin(ctx context.Context) (accountSessionTransaction, error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return nil, roles.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return nil, roles.ErrUnavailable
	}
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return nil, errors.Join(roles.ErrUnavailable, err, rollbackAccountSessionTransaction(tx))
	}
	return tx, nil
}

// workspaceRoleError maps the schema 96 error classes; anything else is uncertain.
func workspaceRoleError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return roles.ErrForbidden
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "42501":
			return roles.ErrForbidden
		case "22023":
			return roles.ErrInvalid
		case "P0002":
			return roles.ErrNotFound
		case "23505", "40001":
			return roles.ErrConflict
		}
	}
	return errors.Join(roles.ErrUnavailable, err)
}

type workspaceDirectoryRecord struct {
	WorkspaceID string `json:"workspace_id"`
	Truncated   bool   `json:"truncated"`
	Members     []struct {
		PrincipalID         string     `json:"principal_id"`
		DisplayName         string     `json:"display_name"`
		MembershipState     string     `json:"membership_state"`
		MembershipExpiresAt *time.Time `json:"membership_expires_at"`
		Owner               bool       `json:"owner"`
		RoleAssignments     []struct {
			AssignmentID string     `json:"assignment_id"`
			Role         string     `json:"role"`
			NetworkID    *string    `json:"network_id"`
			ExpiresAt    *time.Time `json:"expires_at"`
			Version      int64      `json:"version"`
			CreatedAt    time.Time  `json:"created_at"`
		} `json:"role_assignments"`
	} `json:"members"`
}

// ListMembers reads one bounded, freshly authorized member directory.
func (store *WorkspaceRoleStore) ListMembers(ctx context.Context, command roles.ListCommand) (_ roles.Directory, resultErr error) {
	if !command.IsValid() {
		return roles.Directory{}, roles.ErrInvalid
	}
	tx, err := store.begin(ctx)
	if err != nil {
		return roles.Directory{}, err
	}
	defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	var encoded *string
	args := append(sessionQueryArguments(command.Session), command.WorkspaceID.String())
	if err := tx.QueryRow(ctx, listWorkspaceMembersSQL, args...).Scan(&encoded); err != nil {
		return roles.Directory{}, workspaceRoleError(err)
	}
	if encoded == nil {
		return roles.Directory{}, roles.ErrForbidden
	}
	var record workspaceDirectoryRecord
	if err := json.Unmarshal([]byte(*encoded), &record); err != nil {
		return roles.Directory{}, roles.ErrInvalid
	}
	return record.directory()
}

func (record workspaceDirectoryRecord) directory() (roles.Directory, error) {
	workspaceID, err := workspace.ParseID(record.WorkspaceID)
	if err != nil {
		return roles.Directory{}, roles.ErrInvalid
	}
	directory := roles.Directory{WorkspaceID: workspaceID, Truncated: record.Truncated,
		Members: make([]roles.Member, 0, len(record.Members))}
	for _, decoded := range record.Members {
		principalID, err := publicid.Parse(decoded.PrincipalID)
		if err != nil {
			return roles.Directory{}, roles.ErrInvalid
		}
		member := roles.Member{PrincipalID: principalID, DisplayName: decoded.DisplayName,
			MembershipState: decoded.MembershipState, Owner: decoded.Owner,
			Assignments: make([]roles.Assignment, 0, len(decoded.RoleAssignments))}
		if decoded.MembershipExpiresAt != nil {
			member.MembershipExpiresAt = decoded.MembershipExpiresAt.UTC()
		}
		for _, raw := range decoded.RoleAssignments {
			assignment, err := decodeAssignment(raw.AssignmentID, raw.Role, raw.NetworkID, raw.ExpiresAt, raw.Version, raw.CreatedAt)
			if err != nil {
				return roles.Directory{}, err
			}
			member.Assignments = append(member.Assignments, assignment)
		}
		if !member.IsValid() {
			return roles.Directory{}, roles.ErrInvalid
		}
		directory.Members = append(directory.Members, member)
	}
	return directory, nil
}

func decodeAssignment(id, role string, networkID *string, expiresAt *time.Time, version int64, createdAt time.Time) (roles.Assignment, error) {
	assignmentID, err := publicid.Parse(id)
	if err != nil {
		return roles.Assignment{}, roles.ErrInvalid
	}
	builtin, err := authorization.ParseBuiltinRole(role)
	if err != nil {
		return roles.Assignment{}, roles.ErrInvalid
	}
	assignment := roles.Assignment{ID: assignmentID, Role: builtin, Version: version, CreatedAt: createdAt.UTC()}
	if networkID != nil {
		if assignment.NetworkID, err = network.ParseID(*networkID); err != nil {
			return roles.Assignment{}, roles.ErrInvalid
		}
	}
	if expiresAt != nil {
		assignment.ExpiresAt = expiresAt.UTC()
	}
	if !assignment.IsValid() {
		return roles.Assignment{}, roles.ErrInvalid
	}
	return assignment, nil
}

type workspaceRoleActorEvidence struct {
	BindingID            string `json:"role_binding_id,omitempty"`
	RoleID               string `json:"role_definition_id,omitempty"`
	BindingGeneration    int64  `json:"binding_authority_generation"`
	MembershipGeneration int64  `json:"membership_authority_generation"`
	OwnerGeneration      int64  `json:"workspace_owner_authority_generation,omitempty"`
}

// isValid enforces exclusive owner or role evidence, as for Network authority.
func (evidence workspaceRoleActorEvidence) isValid() bool {
	if evidence.MembershipGeneration <= 0 {
		return false
	}
	if evidence.OwnerGeneration > 0 {
		return evidence.BindingID == "" && evidence.RoleID == "" && evidence.BindingGeneration == 0
	}
	return evidence.BindingID != "" && evidence.RoleID != "" && evidence.BindingGeneration > 0
}

// Assign grants one role, appending audit and outbox evidence unless the
// request replays an earlier commit.
func (store *WorkspaceRoleStore) Assign(ctx context.Context, command roles.AssignCommand) (_ roles.AssignResult, resultErr error) {
	if !command.IsValid() {
		return roles.AssignResult{}, roles.ErrInvalid
	}
	ids, err := newWorkspaceRoleEvidenceIDs()
	if err != nil {
		return roles.AssignResult{}, err
	}
	tx, err := store.begin(ctx)
	if err != nil {
		return roles.AssignResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	var networkID, expiresAt any
	if (command.NetworkID != network.ID{}) {
		networkID = command.NetworkID.String()
	}
	if !command.ExpiresAt.IsZero() {
		expiresAt = command.ExpiresAt.UTC()
	}
	args := append(sessionQueryArguments(command.Session), command.WorkspaceID.String(),
		command.AssignmentID.String(), command.PrincipalID.String(), string(command.Role), networkID, expiresAt,
		ids.change.String())
	var returnedID string
	var version int64
	var createdAt time.Time
	var replayed bool
	var actor workspaceRoleActorEvidence
	if err := tx.QueryRow(ctx, assignWorkspaceRoleSQL, args...).Scan(&returnedID, &version, &createdAt, &replayed,
		&actor.BindingID, &actor.RoleID, &actor.BindingGeneration, &actor.MembershipGeneration, &actor.OwnerGeneration); err != nil {
		return roles.AssignResult{}, workspaceRoleError(err)
	}
	if returnedID != command.AssignmentID.String() || version <= 0 || !actor.isValid() {
		return roles.AssignResult{}, roles.ErrInvalid
	}
	assignment := roles.Assignment{ID: command.AssignmentID, Role: command.Role, NetworkID: command.NetworkID,
		ExpiresAt: command.ExpiresAt.UTC(), Version: version, CreatedAt: createdAt.UTC()}
	if command.ExpiresAt.IsZero() {
		assignment.ExpiresAt = time.Time{}
	}
	if !replayed {
		if version != 1 {
			return roles.AssignResult{}, roles.ErrInvalid
		}
		evidence := workspaceRoleChange{Action: "workspace_role.assigned", Session: command.Session,
			WorkspaceID: command.WorkspaceID, AssignmentID: command.AssignmentID, PrincipalID: command.PrincipalID,
			Role: command.Role, NetworkID: command.NetworkID, ExpiresAt: assignment.ExpiresAt,
			Version: version, CorrelationID: command.CorrelationID, Actor: actor}
		if err := appendWorkspaceRoleEvidence(ctx, tx, evidence, ids); err != nil {
			return roles.AssignResult{}, errors.Join(roles.ErrUnavailable, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return roles.AssignResult{}, errors.Join(roles.ErrUnavailable, err)
	}
	committed = true
	return roles.AssignResult{Assignment: assignment, Replayed: replayed}, nil
}

// Revoke ends one assignment at its reviewed version.
func (store *WorkspaceRoleStore) Revoke(ctx context.Context, command roles.RevokeCommand) (_ roles.RevokeResult, resultErr error) {
	if !command.IsValid() {
		return roles.RevokeResult{}, roles.ErrInvalid
	}
	ids, err := newWorkspaceRoleEvidenceIDs()
	if err != nil {
		return roles.RevokeResult{}, err
	}
	tx, err := store.begin(ctx)
	if err != nil {
		return roles.RevokeResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	args := append(sessionQueryArguments(command.Session), command.WorkspaceID.String(),
		command.AssignmentID.String(), command.ExpectedVersion, ids.change.String())
	var returnedID, roleKey, targetID string
	var version int64
	var replayed bool
	var actor workspaceRoleActorEvidence
	if err := tx.QueryRow(ctx, revokeWorkspaceRoleSQL, args...).Scan(&returnedID, &version, &roleKey, &targetID, &replayed,
		&actor.BindingID, &actor.RoleID, &actor.BindingGeneration, &actor.MembershipGeneration, &actor.OwnerGeneration); err != nil {
		return roles.RevokeResult{}, workspaceRoleError(err)
	}
	role, roleErr := authorization.ParseBuiltinRole(roleKey)
	principalID, principalErr := publicid.Parse(targetID)
	if returnedID != command.AssignmentID.String() || version != command.ExpectedVersion+1 || roleErr != nil ||
		principalErr != nil || !actor.isValid() {
		return roles.RevokeResult{}, roles.ErrInvalid
	}
	if !replayed {
		evidence := workspaceRoleChange{Action: "workspace_role.revoked", Session: command.Session,
			WorkspaceID: command.WorkspaceID, AssignmentID: command.AssignmentID, PrincipalID: principalID,
			Role: role, Version: version, CorrelationID: command.CorrelationID, Actor: actor, Revoked: true}
		if err := appendWorkspaceRoleEvidence(ctx, tx, evidence, ids); err != nil {
			return roles.RevokeResult{}, errors.Join(roles.ErrUnavailable, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return roles.RevokeResult{}, errors.Join(roles.ErrUnavailable, err)
	}
	committed = true
	return roles.RevokeResult{AssignmentID: command.AssignmentID, Version: version, Replayed: replayed}, nil
}

type workspaceRoleEvidenceIDs struct{ change, event, outbox publicid.ID }

func newWorkspaceRoleEvidenceIDs() (workspaceRoleEvidenceIDs, error) {
	var ids workspaceRoleEvidenceIDs
	for _, target := range []*publicid.ID{&ids.change, &ids.event, &ids.outbox} {
		id, err := publicid.New()
		if err != nil {
			return workspaceRoleEvidenceIDs{}, roles.ErrUnavailable
		}
		*target = id
	}
	return ids, nil
}

type workspaceRoleChange struct {
	Action        string
	Session       accountsession.Session
	WorkspaceID   workspace.ID
	AssignmentID  publicid.ID
	PrincipalID   publicid.ID
	Role          authorization.BuiltinRole
	NetworkID     network.ID
	ExpiresAt     time.Time
	Version       int64
	CorrelationID publicid.ID
	Actor         workspaceRoleActorEvidence
	Revoked       bool
}

func (change workspaceRoleChange) semanticHash(state string, version int64) ([32]byte, error) {
	var networkID, expiresAt string
	if (change.NetworkID != network.ID{}) {
		networkID = change.NetworkID.String()
	}
	if !change.ExpiresAt.IsZero() {
		expiresAt = change.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	encoded, err := json.Marshal(struct {
		AssignmentID string `json:"assignment_id"`
		WorkspaceID  string `json:"workspace_id"`
		PrincipalID  string `json:"principal_id"`
		Role         string `json:"role"`
		NetworkID    string `json:"network_id,omitempty"`
		ExpiresAt    string `json:"expires_at,omitempty"`
		State        string `json:"state"`
		Version      int64  `json:"version"`
	}{change.AssignmentID.String(), change.WorkspaceID.String(), change.PrincipalID.String(), string(change.Role),
		networkID, expiresAt, state, version})
	return sha256.Sum256(encoded), err
}

func appendWorkspaceRoleEvidence(ctx context.Context, tx accountSessionTransaction, change workspaceRoleChange,
	ids workspaceRoleEvidenceIDs) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, lockWorkspaceStreamHeadSQL, change.Session.DeploymentID().String(), change.WorkspaceID.String()).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return roles.ErrInvalid
	}
	var before, after [32]byte
	var err error
	if change.Revoked {
		if before, err = change.semanticHash("active", change.Version-1); err != nil {
			return err
		}
		after, err = change.semanticHash("revoked", change.Version)
	} else {
		after, err = change.semanticHash("active", change.Version)
	}
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		WorkspaceID  string                     `json:"workspace_id"`
		SessionID    string                     `json:"session_id"`
		PrincipalID  string                     `json:"target_principal_id"`
		Role         string                     `json:"role"`
		NetworkID    string                     `json:"network_id,omitempty"`
		Authority    workspaceRoleActorEvidence `json:"authority"`
		AssignmentID string                     `json:"assignment_id"`
	}{change.WorkspaceID.String(), change.Session.ID().String(), change.PrincipalID.String(), string(change.Role),
		networkIDText(change.NetworkID), change.Actor, change.AssignmentID.String()})
	if err != nil {
		return err
	}
	outbox, err := json.Marshal(struct {
		WorkspaceID  string `json:"workspace_id"`
		AssignmentID string `json:"assignment_id"`
		Version      int64  `json:"version"`
	}{change.WorkspaceID.String(), change.AssignmentID.String(), change.Version})
	if err != nil {
		return err
	}
	var previousHash [32]byte
	copy(previousHash[:], previous)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: ids.event, ChangeID: ids.change,
		AggregateKind: "workspace_role_assignment", AggregateID: change.AssignmentID, AggregateVersion: change.Version,
		ActorPrincipalID: publicid.ID(change.Session.PrincipalID()), Action: change.Action,
		Permission: string(authorization.PermissionRoleBindingManage), CorrelationID: change.CorrelationID,
		BeforeSemanticHash: before, AfterSemanticHash: after, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: change.Action, OutboxPayloadHash: sha256.Sum256(outbox),
	})
	if err != nil {
		return err
	}
	var beforeArgument any
	if change.Revoked {
		beforeArgument = before[:]
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendWorkspaceRoleEvidenceSQL, streamID, ids.event.String(), ids.outbox.String(), sequence,
		previousHash[:], eventHash[:], change.AssignmentID.String(), change.Version,
		change.Session.PrincipalID().String(), change.Action, change.CorrelationID.String(), beforeArgument, after[:],
		payload, outbox).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return roles.ErrInvalid
	}
	return nil
}

func networkIDText(id network.ID) string {
	if (id == network.ID{}) {
		return ""
	}
	return id.String()
}

var _ roles.Store = (*WorkspaceRoleStore)(nil)

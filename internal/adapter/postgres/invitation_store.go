package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/invitation"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const changeWorkspaceInvitationSQL = `SELECT mesh_ops.change_workspace_invitation_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::TEXT,$13::TEXT,$14::TEXT,$15::BYTEA,$16::TIMESTAMPTZ,$17::BIGINT,$18::UUID,
 $19::TIMESTAMPTZ)::TEXT`

const listWorkspaceInvitationsSQL = `SELECT mesh_ops.list_workspace_invitations_v1(` + sessionArguments + `,
 $10::UUID,$11::TIMESTAMPTZ)::TEXT`

// InvitationStore commits Workspace invitation changes through the runtime
// pool, each with evidence on the Workspace stream. Token digests are passed
// in and never read back.
type InvitationStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ invitation.Store = (*InvitationStore)(nil)

// NewInvitationStore uses the runtime pool.
func NewInvitationStore(pool *Pool, options AccountSessionOptions) (*InvitationStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, invitation.ErrInvalid
	}
	return &InvitationStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func (store *InvitationStore) transact(ctx context.Context,
	run func(tx accountSessionTransaction) (bool, error)) (resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return invitation.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return errors.Join(invitation.ErrUnavailable, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return errors.Join(invitation.ErrUnavailable, err)
	}
	commit, err := run(tx)
	if err != nil || !commit {
		return err
	}
	committed = true
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(invitation.ErrUnavailable, err)
	}
	return nil
}

func invitationDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501", "23503":
			return invitation.ErrForbidden
		case "P0002":
			return invitation.ErrNotFound
		case "40001":
			return invitation.ErrVersionConflict
		case "MTV01", "23505":
			return invitation.ErrAlreadyInvited
		case "MTV02":
			return invitation.ErrTooMany
		case "MTV03":
			return invitation.ErrNotPending
		case "MTV04":
			return invitation.ErrTooSoon
		case "22023", "22P02", "23514":
			return invitation.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return invitation.ErrForbidden
	}
	return errors.Join(invitation.ErrUnavailable, err)
}

type invitationPersonDocument struct {
	PrincipalID string `json:"principal_id"`
	DisplayName string `json:"display_name"`
}

type invitationDocument struct {
	ID            string                   `json:"invitation_id"`
	Email         string                   `json:"email"`
	Role          *string                  `json:"role"`
	State         string                   `json:"state"`
	ExpiresAt     time.Time                `json:"expires_at"`
	InvitedBy     invitationPersonDocument `json:"invited_by"`
	DeliveryState string                   `json:"delivery_state"`
	LastSentAt    *time.Time               `json:"last_sent_at"`
	SendCount     int                      `json:"send_count"`
	CreatedAt     time.Time                `json:"created_at"`
	Version       int64                    `json:"version"`
}

func (document invitationDocument) invitation() (invitation.Invitation, error) {
	id, err := publicid.Parse(document.ID)
	inviter, inviterErr := publicid.Parse(document.InvitedBy.PrincipalID)
	email, emailOK := invitation.NormalizeEmail(document.Email)
	states := map[string]bool{"pending": true, "accepted": true, "revoked": true, "expired": true}
	deliveries := map[string]bool{"pending": true, "sent": true, "failed": true, "not_configured": true}
	if err != nil || inviterErr != nil || !emailOK || email != document.Email || !states[document.State] ||
		!deliveries[document.DeliveryState] || document.Version < 1 || document.SendCount < 0 ||
		document.ExpiresAt.IsZero() || document.CreatedAt.IsZero() {
		return invitation.Invitation{}, invitation.ErrInvalid
	}
	result := invitation.Invitation{
		ID: id, Email: email, State: document.State, ExpiresAt: document.ExpiresAt,
		InvitedBy:     invitation.Person{PrincipalID: inviter, DisplayName: document.InvitedBy.DisplayName},
		DeliveryState: document.DeliveryState, LastSentAt: document.LastSentAt, SendCount: document.SendCount,
		CreatedAt: document.CreatedAt, Version: document.Version,
	}
	if document.Role != nil {
		result.Role = *document.Role
	}
	return result, nil
}

type invitationChangeRecord struct {
	Before        *invitationDocument `json:"before"`
	Invitation    invitationDocument  `json:"invitation"`
	WorkspaceName string              `json:"workspace_name"`
	Authority     catalogAuthority    `json:"authority"`
}

func invitationSemanticHash(value invitation.Invitation) ([32]byte, error) {
	encoded, err := json.Marshal(struct {
		ID            string    `json:"invitation_id"`
		Email         string    `json:"email"`
		Role          string    `json:"role"`
		State         string    `json:"state"`
		ExpiresAt     time.Time `json:"expires_at"`
		DeliveryState string    `json:"delivery_state"`
	}{value.ID.String(), value.Email, value.Role, value.State, value.ExpiresAt.UTC(), value.DeliveryState})
	return sha256.Sum256(encoded), err
}

// invitationAction is the audit action of each change.
var invitationAction = map[invitation.Action]string{
	invitation.ActionCreate:         "member.invited",
	invitation.ActionResend:         "member.invitation_resent",
	invitation.ActionRevoke:         "member.invitation_revoked",
	invitation.ActionDelivered:      "member.invitation_delivered",
	invitation.ActionDeliveryFailed: "member.invitation_delivery_failed",
	invitation.ActionNotConfigured:  "member.invitation_not_emailed",
}

// Change authorizes member.invite, applies the change and commits it with
// its evidence. The evidence names the invitation, never the address.
func (store *InvitationStore) Change(ctx context.Context, change invitation.Change) (invitation.ChangeResult, error) {
	if !change.IsValid() {
		return invitation.ChangeResult{}, invitation.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return invitation.ChangeResult{}, invitation.ErrUnavailable
	}
	var email, role, digest, expires, expected any
	if change.Email != "" {
		email = change.Email
	}
	if change.Role != "" {
		role = change.Role
	}
	if change.TokenDigest != nil {
		value := *change.TokenDigest
		digest = value[:]
		expires = change.ExpiresAt
	}
	if change.ExpectedVersion > 0 {
		expected = change.ExpectedVersion
	}
	var result invitation.ChangeResult
	err = store.transact(ctx, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, changeWorkspaceInvitationSQL, append(sessionQueryArguments(change.Session),
			change.WorkspaceID.String(), change.InvitationID.String(), string(change.Action), email, role, digest,
			expires, expected, changeID.String(), change.EvaluatedAt)...).Scan(&encoded); err != nil {
			return false, invitationDatabaseError(err)
		}
		var record invitationChangeRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil {
			return false, invitation.ErrInvalid
		}
		saved, err := record.Invitation.invitation()
		if err != nil || saved.ID != change.InvitationID || (change.Action == invitation.ActionCreate) != (record.Before == nil) {
			return false, invitation.ErrInvalid
		}
		result = invitation.ChangeResult{Invitation: saved, WorkspaceName: record.WorkspaceName}
		var beforeHash *[32]byte
		if record.Before != nil {
			before, err := record.Before.invitation()
			if err != nil {
				return false, err
			}
			result.Before = &before
			hash, err := invitationSemanticHash(before)
			if err != nil {
				return false, err
			}
			beforeHash = &hash
		}
		afterHash, err := invitationSemanticHash(saved)
		if err != nil {
			return false, err
		}
		action := invitationAction[change.Action]
		event := catalogEvent{
			session: change.Session, correlationID: change.CorrelationID, changeID: changeID,
			aggregateKind: "workspace_invitation", aggregateID: saved.ID, version: saved.Version,
			action: action, permission: "member.invite", before: beforeHash, after: afterHash,
			payload: struct {
				WorkspaceID   string           `json:"workspace_id"`
				SessionID     string           `json:"session_id"`
				InvitationID  string           `json:"invitation_id"`
				Role          string           `json:"role,omitempty"`
				ExpiresAt     time.Time        `json:"expires_at"`
				DeliveryState string           `json:"delivery_state"`
				Authority     catalogAuthority `json:"authority"`
			}{change.WorkspaceID.String(), change.Session.ID().String(), saved.ID.String(), saved.Role,
				saved.ExpiresAt.UTC(), saved.DeliveryState, record.Authority},
			outboxClass: action,
			outbox: struct {
				WorkspaceID  string `json:"workspace_id"`
				InvitationID string `json:"invitation_id"`
				Version      int64  `json:"version"`
			}{change.WorkspaceID.String(), saved.ID.String(), saved.Version},
		}
		if err := appendWorkspaceCatalogEvent(ctx, tx, change.WorkspaceID, event); err != nil {
			return false, errors.Join(invitation.ErrUnavailable, err)
		}
		return true, nil
	})
	if err != nil {
		return invitation.ChangeResult{}, err
	}
	return result, nil
}

// List reads the Workspace's invitations (member.invite).
func (store *InvitationStore) List(ctx context.Context, session accountsession.Session, workspaceID workspace.ID,
	now time.Time) ([]invitation.Invitation, error) {
	if !session.IsValid() || !workspaceID.IsValid() || now.IsZero() {
		return nil, invitation.ErrInvalid
	}
	var listed []invitation.Invitation
	err := store.transact(ctx, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, listWorkspaceInvitationsSQL, append(sessionQueryArguments(session),
			workspaceID.String(), now)...).Scan(&encoded); err != nil {
			return false, invitationDatabaseError(err)
		}
		var record struct {
			Invitations []invitationDocument `json:"invitations"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil || record.Invitations == nil {
			return false, invitation.ErrInvalid
		}
		listed = make([]invitation.Invitation, 0, len(record.Invitations))
		for _, document := range record.Invitations {
			value, err := document.invitation()
			if err != nil {
				return false, err
			}
			listed = append(listed, value)
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return listed, nil
}

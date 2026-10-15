package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/identity/oidcauth"
	"meshtransit.net/core/internal/domain/invitation"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// Schema 160: the invitation is consumed only when $17, the address the
// provider verified for this sign-in, equals the invited address.
const acceptWorkspaceInvitationSQL = `SELECT mesh_ops.accept_workspace_invitation_v2(
 $1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::UUID,$7::BIGINT,$8::BYTEA,$9::TIMESTAMPTZ,
 $10::TEXT,$11::TEXT,$12::BYTEA,$13::TEXT,$14::BYTEA,$15::BYTEA,$16::UUID,$17::TEXT)::TEXT`

// invitationEmailDigestDomain separates the evidence digest of an accepting
// address from every other digest.
const invitationEmailDigestDomain = "meshtransit-invitation-email-v1\x00"

const previewWorkspaceInvitationSQL = `SELECT COALESCE(mesh_ops.preview_workspace_invitation_v1($1::BYTEA,
 $2::TIMESTAMPTZ)::TEXT, '')`

var _ oidcauth.InvitationAcceptor = (*InvitationStore)(nil)

type invitationAcceptanceRecord struct {
	InvitationID      string  `json:"invitation_id"`
	InvitationVersion int64   `json:"invitation_version"`
	WorkspaceID       string  `json:"workspace_id"`
	PrincipalID       string  `json:"principal_id"`
	AccountCreated    *bool   `json:"account_created"`
	Joined            *bool   `json:"joined"`
	NetworkCount      *int    `json:"network_count"`
	Role              *string `json:"role"`
}

func invitationAcceptanceError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "P0002", "MTV05", "MTV06", "42501", "22023", "23505":
			return oidcauth.ErrInvitationRejected
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return oidcauth.ErrInvitationRejected
	}
	return errors.Join(oidcauth.ErrInvitationUnavailable, err)
}

// AcceptInvitation commits the membership an invitation grants to the identity
// of one consuming sign-in, with evidence on the Workspace stream whose actor
// is the accepting principal. The sign-in then resolves the subject as usual.
func (store *InvitationStore) AcceptInvitation(ctx context.Context, acceptance oidcauth.InvitationAcceptance) error {
	if !acceptance.Lookup.IsValid() || !acceptance.Proof.IsValid() || acceptance.Email == "" {
		return oidcauth.ErrInvitationRejected
	}
	changeID, err := publicid.New()
	if err != nil {
		return oidcauth.ErrInvitationUnavailable
	}
	snapshot := acceptance.Lookup.Snapshot()
	route, claimed, digests := snapshot.Route(), acceptance.Lookup.Claimed(), acceptance.Lookup.Digests()
	active := digests[0].Bytes()
	var previousID *string
	var previousBytes []byte
	if len(digests) == 2 {
		id := digests[1].KeyID().String()
		previousID = &id
		previous := digests[1].Bytes()
		previousBytes = previous[:]
	}
	hash := snapshot.SemanticHash()
	token := acceptance.Proof.Digest()
	// Evidence names the accepting address by a digest, never in clear.
	emailDigest := sha256.Sum256([]byte(invitationEmailDigestDomain + strings.ToLower(acceptance.Email)))
	return store.transact(ctx, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, acceptWorkspaceInvitationSQL, route.DeploymentID().String(),
			route.ProviderID().String(), route.ClientID().String(), route.ProviderGeneration(), route.RecoveryEpoch(),
			snapshot.TransactionID().String(), claimed.Version(), hash[:], claimed.ConsumedAt(),
			digests[0].Algorithm(), digests[0].KeyID().String(), active[:], previousID, previousBytes, token[:],
			changeID.String(), acceptance.Email).Scan(&encoded); err != nil {
			return false, invitationAcceptanceError(err)
		}
		var record invitationAcceptanceRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil || record.AccountCreated == nil ||
			record.Joined == nil || record.NetworkCount == nil || record.InvitationVersion < 2 {
			return false, oidcauth.ErrInvitationUnavailable
		}
		invitationID, invitationErr := publicid.Parse(record.InvitationID)
		principal, principalErr := publicid.Parse(record.PrincipalID)
		workspaceID, workspaceErr := workspace.ParseID(record.WorkspaceID)
		if invitationErr != nil || principalErr != nil || workspaceErr != nil {
			return false, oidcauth.ErrInvitationUnavailable
		}
		role := ""
		if record.Role != nil {
			role = *record.Role
		}
		after := sha256.Sum256([]byte("accepted\x00" + invitationID.String() + "\x00" + principal.String()))
		event := catalogEvent{
			correlationID: changeID, changeID: changeID, aggregateKind: "workspace_invitation",
			aggregateID: invitationID, version: record.InvitationVersion, action: "member.invitation_accepted",
			permission: "member.invite", after: after, actor: principal, deployment: route.DeploymentID().String(),
			payload: struct {
				WorkspaceID    string `json:"workspace_id"`
				InvitationID   string `json:"invitation_id"`
				PrincipalID    string `json:"principal_id"`
				AccountCreated bool   `json:"account_created"`
				Joined         bool   `json:"joined"`
				NetworkCount   int    `json:"network_count"`
				Role           string `json:"role,omitempty"`
				Transaction    string `json:"auth_transaction_id"`
				EmailDigest    string `json:"verified_email_sha256"`
			}{workspaceID.String(), invitationID.String(), principal.String(), *record.AccountCreated, *record.Joined,
				*record.NetworkCount, role, snapshot.TransactionID().String(), hex.EncodeToString(emailDigest[:])},
			outboxClass: "member.invitation_accepted",
			outbox: struct {
				WorkspaceID  string `json:"workspace_id"`
				InvitationID string `json:"invitation_id"`
				PrincipalID  string `json:"principal_id"`
			}{workspaceID.String(), invitationID.String(), principal.String()},
		}
		if err := appendWorkspaceCatalogEvent(ctx, tx, workspaceID, event); err != nil {
			return false, errors.Join(oidcauth.ErrInvitationUnavailable, err)
		}
		return true, nil
	})
}

type invitationPreviewDocument struct {
	WorkspaceName string    `json:"workspace_name"`
	InviterName   string    `json:"inviter_name"`
	Email         string    `json:"email"`
	Role          *string   `json:"role"`
	ExpiresAt     time.Time `json:"expires_at"`
}

// PreviewInvitation reads a pending, unexpired invitation by token digest.
func (store *InvitationStore) PreviewInvitation(ctx context.Context, digest [32]byte, now time.Time) (
	invitation.Preview, error) {
	if digest == [32]byte{} || now.IsZero() {
		return invitation.Preview{}, invitation.ErrInvalid
	}
	var preview invitation.Preview
	err := store.transact(ctx, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, previewWorkspaceInvitationSQL, digest[:], now).Scan(&encoded); err != nil {
			return false, invitationDatabaseError(err)
		}
		if encoded == "" {
			return false, invitation.ErrNotFound
		}
		var document invitationPreviewDocument
		if err := decodeIdentityCatalogJSON([]byte(encoded), &document); err != nil || document.ExpiresAt.IsZero() {
			return false, invitation.ErrInvalid
		}
		preview = invitation.Preview{
			WorkspaceName: document.WorkspaceName, InviterName: document.InviterName, Email: document.Email,
			ExpiresAt: document.ExpiresAt,
		}
		if document.Role != nil {
			preview.Role = *document.Role
		}
		return false, nil
	})
	if err != nil {
		return invitation.Preview{}, err
	}
	return preview, nil
}

//go:build integration

package integration

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/invitation"
)

// assertPostgreSQLInvitations qualifies schema 128 through the production
// store: the owner invites an address (link-only without a mailer), a second
// pending invitation for the address and a plain member's invitation are
// refused, resending rotates the stored digest and version, revoking ends the
// invitation, and only digests ever reach the table.
func assertPostgreSQLInvitations(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewInvitationStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := invitation.NewService(invitation.Options{
		Store: store, Clock: accountsession.SystemClock{}, ConsoleOrigin: "https://console.example.test",
		SendTimeout: time.Second, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	plain := authorityConfirmerAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	create := func(session accountsession.Session, email, role string) (invitation.Sent, error) {
		return service.Create(ctx, session, invitation.CreateRequest{
			WorkspaceID: workspaceID, Email: email, Role: role, CorrelationID: newCorrelationID(t),
		})
	}

	sent, err := create(owner, "Invitee@Example.test", "auditor")
	if err != nil || sent.Invitation.State != "pending" || sent.Invitation.Email != "invitee@example.test" ||
		sent.Invitation.Role != "auditor" || sent.Invitation.DeliveryState != "not_configured" ||
		!strings.HasPrefix(sent.Link, "https://console.example.test/join#invite=") {
		t.Fatalf("create = %+v, %v", sent, err)
	}
	token, ok := invitation.ParseToken(strings.TrimPrefix(sent.Link, "https://console.example.test/join#invite="))
	if !ok {
		t.Fatal("the link must carry a canonical token")
	}
	digest := token.Digest()
	if stored := invitationDigest(ctx, t, admin, sent.Invitation.ID.String()); string(stored) != string(digest[:]) {
		t.Fatal("the table must hold the token digest")
	}
	if _, err := create(owner, "invitee@example.test", ""); !errors.Is(err, invitation.ErrAlreadyInvited) {
		t.Fatalf("second pending invitation: %v", err)
	}
	if _, err := create(plain, "other@example.test", ""); !errors.Is(err, invitation.ErrForbidden) {
		t.Fatalf("plain member invited: %v", err)
	}
	listed, err := service.List(ctx, owner, workspaceID)
	if err != nil || len(listed) == 0 || listed[0].ID != sent.Invitation.ID {
		t.Fatalf("list = %+v, %v", listed, err)
	}

	// The last delivery was not recorded as sent, so resend is not throttled.
	resent, err := service.Resend(ctx, owner, invitation.ActionRequest{
		WorkspaceID: workspaceID, InvitationID: sent.Invitation.ID, ExpectedVersion: sent.Invitation.Version,
		CorrelationID: newCorrelationID(t),
	})
	if err != nil || resent.Link == sent.Link || resent.Invitation.Version <= sent.Invitation.Version {
		t.Fatalf("resend = %+v, %v", resent, err)
	}
	if stored := invitationDigest(ctx, t, admin, sent.Invitation.ID.String()); string(stored) == string(digest[:]) {
		t.Fatal("resend must rotate the digest")
	}
	revoked, err := service.Revoke(ctx, owner, invitation.ActionRequest{
		WorkspaceID: workspaceID, InvitationID: sent.Invitation.ID, ExpectedVersion: resent.Invitation.Version,
		CorrelationID: newCorrelationID(t),
	})
	if err != nil || revoked.State != "revoked" {
		t.Fatalf("revoke = %+v, %v", revoked, err)
	}
	if _, err := service.Revoke(ctx, owner, invitation.ActionRequest{
		WorkspaceID: workspaceID, InvitationID: sent.Invitation.ID, ExpectedVersion: revoked.Version,
		CorrelationID: newCorrelationID(t),
	}); !errors.Is(err, invitation.ErrNotPending) {
		t.Fatalf("revoked twice: %v", err)
	}
}

func invitationDigest(ctx context.Context, t *testing.T, admin *pgx.Conn, id string) []byte {
	t.Helper()
	var digest []byte
	if err := admin.QueryRow(ctx, `SELECT token_digest FROM mesh.workspace_invitation WHERE public_id = $1::UUID`, id).
		Scan(&digest); err != nil {
		t.Fatal(err)
	}
	return digest
}

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
	adapteroidc "github.com/meshtransit/meshtransit/core/internal/adapter/oidc"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"github.com/meshtransit/meshtransit/core/internal/domain/invitation"
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

// assertPostgreSQLInvitationAcceptance qualifies schema 129 through the
// production stores and a real claimed, exchanged sign-in: an invitation to
// Workspace 101 makes a never-seen identity an Account and a member with the
// invited role and every active Network, the sign-in then resolves to that
// Workspace, and the link cannot be used again.
func assertPostgreSQLInvitationAcceptance(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	authStore, err := postgresadapter.NewAuthTransactionStore(runtimePool, postgresadapter.AuthTransactionOptions{
		StatementTimeout: 10 * time.Second, LockTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	invitations, err := postgresadapter.NewInvitationStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	token, err := invitation.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	digest := token.Digest()
	const invitationID = "01890f00-0000-7000-8000-000000001971"
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `RESET ROLE; SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mesh.workspace_invitation (public_id, deployment_id, workspace_id, email,
    role_key, token_digest, expires_at, invited_by_principal_id, created_at, updated_at)
VALUES ($1::UUID, 1, 101, 'newcomer@example.test', 'auditor', $2, now() + INTERVAL '1 day', 11, now(), now())`,
		invitationID, digest[:]); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	preview, err := invitations.PreviewInvitation(ctx, digest, time.Now())
	if err != nil || preview.Email != "newcomer@example.test" || preview.Role != "auditor" || preview.WorkspaceName == "" {
		t.Fatalf("preview = %+v, %v", preview, err)
	}

	keys, err := oidcauth.NewSubjectKeyring(integrationSubjectKey(t, "invitation-subject-v1", 0x71))
	if err != nil {
		t.Fatal(err)
	}
	accept := func(suffix string) (oidcauth.ExchangeResult, error) {
		exchange, route := integrationSubjectExchangeWithProfile(ctx, t, authStore, suffix, integrationSubjectProfile{})
		digests, err := keys.Digests(route, exchange.Identity())
		if err != nil {
			t.Fatal(err)
		}
		lookup, err := oidcauth.NewSubjectLookup(exchange.Claimed(), digests)
		if err != nil {
			t.Fatal(err)
		}
		return exchange, invitations.AcceptInvitation(ctx, oidcauth.InvitationAcceptance{
			Lookup: lookup, Proof: oidcauth.NewInvitationProof(digest),
		})
	}
	exchange, err := accept("e71")
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	var state, displayName string
	var memberships, roles, networks, activeNetworks int64
	if err := admin.QueryRow(ctx, `SELECT invitation.state, account.display_name,
    (SELECT count(*) FROM mesh.workspace_membership AS m WHERE m.principal_id = invitation.accepted_by_principal_id
       AND m.workspace_id = 101 AND m.state = 'active'),
    (SELECT count(*) FROM mesh.workspace_role_assignment AS r WHERE r.principal_id = invitation.accepted_by_principal_id
       AND r.role_key = 'auditor' AND r.state = 'active'),
    (SELECT count(*) FROM mesh.network_membership AS n WHERE n.principal_id = invitation.accepted_by_principal_id),
    (SELECT count(*) FROM mesh.network AS n WHERE n.workspace_id = 101 AND n.state = 'active' AND n.deleted_at IS NULL)
FROM mesh.workspace_invitation AS invitation
JOIN mesh.account AS account ON account.principal_id = invitation.accepted_by_principal_id
WHERE invitation.public_id = $1::UUID`, invitationID).Scan(&state, &displayName, &memberships, &roles, &networks,
		&activeNetworks); err != nil {
		t.Fatal(err)
	}
	if state != "accepted" || displayName != "newcomer@example.test" || memberships != 1 || roles != 1 ||
		networks != activeNetworks {
		t.Fatalf("accepted = %s %s members=%d roles=%d networks=%d/%d", state, displayName, memberships, roles,
			networks, activeNetworks)
	}
	resolver, err := oidcauth.NewSubjectResolutionService(
		oidcauth.SubjectResolutionOptions{RequestTimeout: 10 * time.Second, MaxConcurrent: 1},
		oidcauth.SubjectResolutionDependencies{Subjects: authStore, Keys: keys, Clock: oidcauth.SystemStartClock{},
			Observer: adapteroidc.NewSubjectTelemetry()})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveBrowser(ctx, exchange)
	if err != nil || resolved.WorkspaceID().String() != integrationLoginWorkspacePublicID {
		t.Fatalf("the new member must resolve into the invited Workspace: %v", err)
	}
	if _, err := accept("e72"); !errors.Is(err, oidcauth.ErrInvitationRejected) {
		t.Fatalf("a used link must be refused: %v", err)
	}
}

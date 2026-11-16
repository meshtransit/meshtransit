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
	adapteroidc "meshtransit.net/core/internal/adapter/oidc"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
	"meshtransit.net/core/internal/domain/invitation"
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

	// Schema 183: created while another Workspace change holds the row.
	sent, err := runWhileWorkspaceShared(ctx, t, admin, "change_workspace_invitation_v1",
		func() (invitation.Sent, error) { return create(owner, "Invitee@Example.test", "auditor") })
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
	// The create committed version 1; recording the delivery outcome came after.
	assertInvitationExpiryOnDatabaseClock(ctx, t, admin, sent.Invitation.ID.String(), 1, invitation.Lifetime)
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
	// The resend committed the version after the one it expected; recording
	// its delivery outcome came after.
	assertInvitationExpiryOnDatabaseClock(ctx, t, admin, sent.Invitation.ID.String(), sent.Invitation.Version+1,
		invitation.Lifetime)
	// Schema 293 (TD-SEC-79): an it_admin, who may invite but not grant
	// admin, can neither resend nor revoke the owner's admin invitation.
	elevated, err := create(owner, "admin-invitee@example.test", "admin")
	if err != nil {
		t.Fatalf("owner admin invitation: %v", err)
	}
	removeITAdmin := seedEnrollmentKeyRole(ctx, t, admin, plain, 1997, "it_admin")
	for name, act := range map[string]func() error{
		"resend": func() error {
			_, err := service.Resend(ctx, plain, invitation.ActionRequest{WorkspaceID: workspaceID,
				InvitationID: elevated.Invitation.ID, ExpectedVersion: elevated.Invitation.Version,
				CorrelationID: newCorrelationID(t)})
			return err
		},
		"revoke": func() error {
			_, err := service.Revoke(ctx, plain, invitation.ActionRequest{WorkspaceID: workspaceID,
				InvitationID: elevated.Invitation.ID, ExpectedVersion: elevated.Invitation.Version,
				CorrelationID: newCorrelationID(t)})
			return err
		},
	} {
		if err := act(); !errors.Is(err, invitation.ErrForbidden) {
			t.Fatalf("it_admin %s of an admin invitation: %v", name, err)
		}
	}
	// Within the ceiling the it_admin still resends and revokes.
	roleless, err := create(plain, "roleless-invitee@example.test", "")
	if err != nil {
		t.Fatalf("it_admin role-less invitation: %v", err)
	}
	resentRoleless, err := service.Resend(ctx, plain, invitation.ActionRequest{WorkspaceID: workspaceID,
		InvitationID: roleless.Invitation.ID, ExpectedVersion: roleless.Invitation.Version,
		CorrelationID: newCorrelationID(t)})
	if err != nil {
		t.Fatalf("it_admin resend of a role-less invitation: %v", err)
	}
	if _, err := service.Revoke(ctx, plain, invitation.ActionRequest{WorkspaceID: workspaceID,
		InvitationID: roleless.Invitation.ID, ExpectedVersion: resentRoleless.Invitation.Version,
		CorrelationID: newCorrelationID(t)}); err != nil {
		t.Fatalf("it_admin revoke of a role-less invitation: %v", err)
	}
	removeITAdmin()
	if _, err := service.Revoke(ctx, owner, invitation.ActionRequest{WorkspaceID: workspaceID,
		InvitationID: elevated.Invitation.ID, ExpectedVersion: elevated.Invitation.Version,
		CorrelationID: newCorrelationID(t)}); err != nil {
		t.Fatalf("owner revoke of the admin invitation: %v", err)
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
VALUES ($1::UUID, 1, 101, 'newcomer.k@example.test', 'auditor', $2, now() + INTERVAL '1 day', 11, now(), now())`,
		invitationID, digest[:]); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	preview, err := invitations.PreviewInvitation(ctx, digest)
	if err != nil || preview.Email != "newcomer.k@example.test" || preview.Role != "auditor" || preview.WorkspaceName == "" {
		t.Fatalf("preview = %+v, %v", preview, err)
	}

	keys, err := oidcauth.NewSubjectKeyring(integrationSubjectKey(t, "invitation-subject-v1", 0x71))
	if err != nil {
		t.Fatal(err)
	}
	accept := func(suffix, email string) (oidcauth.ExchangeResult, error) {
		exchange, route := integrationSubjectExchangeWithProfile(ctx, t, authStore, suffix,
			integrationSubjectProfile{email: email})
		digests, err := keys.Digests(route, exchange.Identity())
		if err != nil {
			t.Fatal(err)
		}
		lookup, err := oidcauth.NewSubjectLookup(exchange.Claimed(), digests)
		if err != nil {
			t.Fatal(err)
		}
		return exchange, invitations.AcceptInvitation(ctx, oidcauth.InvitationAcceptance{
			Lookup: lookup, Proof: oidcauth.NewInvitationProof(digest), Email: exchange.Identity().Profile().Email(),
		})
	}
	// The link alone is not enough: a sign-in that proves another address, a
	// non-ASCII lookalike (the Kelvin sign folds to "k" under lower()), or no
	// address is refused, and nothing is created or consumed.
	before := invitationAuthorityCounts(ctx, t, admin)
	for _, refused := range []struct{ suffix, email string }{
		{suffix: "e70", email: "someone.else@example.test"},
		{suffix: "e74", email: "newcomer.\u212a@example.test"},
		{suffix: "e73", email: ""},
	} {
		if _, err := accept(refused.suffix, refused.email); !errors.Is(err, oidcauth.ErrInvitationRejected) {
			t.Fatalf("accept(%q) = %v, want ErrInvitationRejected", refused.email, err)
		}
	}
	var pendingState string
	if err := admin.QueryRow(ctx, `SELECT state FROM mesh.workspace_invitation WHERE public_id = $1::UUID`,
		invitationID).Scan(&pendingState); err != nil {
		t.Fatal(err)
	}
	if after := invitationAuthorityCounts(ctx, t, admin); pendingState != "pending" || after != before {
		t.Fatalf("after refused sign-ins: invitation %s, authority %+v, want %+v", pendingState, after, before)
	}
	exchange, err := accept("e71", "Newcomer.K@Example.test")
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
	if state != "accepted" || displayName != "Newcomer.K@Example.test" || memberships != 1 || roles != 1 ||
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
	if _, err := accept("e72", "newcomer.k@example.test"); !errors.Is(err, oidcauth.ErrInvitationRejected) {
		t.Fatalf("a used link must be refused: %v", err)
	}

	// A member cannot raise their own role through a link sent to someone
	// else: the admin invitation for another address stays pending.
	adminToken, err := invitation.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	adminDigest := adminToken.Digest()
	const adminInvitationID = "01890f00-0000-7000-8000-000000001972"
	tx, err = admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `RESET ROLE; SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mesh.workspace_invitation (public_id, deployment_id, workspace_id, email,
    role_key, token_digest, expires_at, invited_by_principal_id, created_at, updated_at)
VALUES ($1::UUID, 1, 101, 'boss@example.test', 'admin', $2, now() + INTERVAL '1 day', 11, now(), now())`,
		adminInvitationID, adminDigest[:]); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	digest = adminDigest
	before = invitationAuthorityCounts(ctx, t, admin)
	if _, err := accept("e75", "Newcomer.K@Example.test"); !errors.Is(err, oidcauth.ErrInvitationRejected) {
		t.Fatalf("a member using an admin link for another address = %v, want ErrInvitationRejected", err)
	}
	if after := invitationAuthorityCounts(ctx, t, admin); after != before {
		t.Fatalf("a refused member link changed authority: %+v, want %+v", after, before)
	}

	// Schema 294 (TD-SEC-84, TD-SEC-85): a role comes only with joining, and
	// only while the inviter may still invite and grant that role.
	var newcomer int64
	if err := admin.QueryRow(ctx, `SELECT accepted_by_principal_id FROM mesh.workspace_invitation
WHERE public_id = $1::UUID`, invitationID).Scan(&newcomer); err != nil {
		t.Fatal(err)
	}
	invite := func(id, email, role string, inviter int64) {
		t.Helper()
		next, err := invitation.NewToken()
		if err != nil {
			t.Fatal(err)
		}
		nextDigest := next.Digest()
		var rolePtr *string
		if role != "" {
			rolePtr = &role
		}
		runInvitationFixture(ctx, t, admin, `INSERT INTO mesh.workspace_invitation (public_id, deployment_id,
    workspace_id, email, role_key, token_digest, expires_at, invited_by_principal_id, created_at, updated_at)
VALUES ($1::UUID, 1, 101, $2, $3, $4, now() + INTERVAL '1 day', $5, now(), now())`,
			id, email, rolePtr, nextDigest[:], inviter)
		digest = nextDigest
	}
	refuse := func(name, suffix, email string) {
		t.Helper()
		before := invitationAuthorityCounts(ctx, t, admin)
		if _, err := accept(suffix, email); !errors.Is(err, oidcauth.ErrInvitationRejected) {
			t.Fatalf("%s = %v, want ErrInvitationRejected", name, err)
		}
		if after := invitationAuthorityCounts(ctx, t, admin); after != before {
			t.Fatalf("%s changed authority: %+v, want %+v", name, after, before)
		}
	}
	// A member cannot add a role to themselves through a link to their own
	// address, even one the owner sent: roles of members go through role
	// assignment and its ceiling.
	invite("01890f00-0000-7000-8000-000000001973", "newcomer.k@example.test", "it_admin", 11)
	refuse("a member taking a role through their own link", "e76", "Newcomer.K@Example.test")
	runInvitationFixture(ctx, t, admin, `UPDATE mesh.workspace_invitation SET state = 'revoked', revoked_at = now(),
    version = version + 1, updated_at = now() WHERE public_id = $1::UUID`, "01890f00-0000-7000-8000-000000001973")

	// Another person from here on: the fake provider has one subject, so a
	// different subject key makes a different identity.
	keys, err = oidcauth.NewSubjectKeyring(integrationSubjectKey(t, "invitation-subject-v1", 0x72))
	if err != nil {
		t.Fatal(err)
	}
	// An inviter who may not invite (the newcomer is an auditor) has nothing
	// to pass on, with or without a role.
	invite("01890f00-0000-7000-8000-000000001974", "late.joiner@example.test", "", newcomer)
	refuse("an invitation from a member who may not invite", "e77", "late.joiner@example.test")
	runInvitationFixture(ctx, t, admin, `UPDATE mesh.workspace_invitation SET role_key = 'auditor'
WHERE public_id = $1::UUID`, "01890f00-0000-7000-8000-000000001974")
	refuse("a role invitation from a member who may not invite", "e7a", "late.joiner@example.test")

	// As it_admin the newcomer invites and grants it_admin, but not a role
	// beyond it (network_admin), and nothing once the role is gone.
	runInvitationFixture(ctx, t, admin, `INSERT INTO mesh.workspace_role_assignment (public_id, deployment_id,
    workspace_id, principal_id, workspace_membership_id, role_key, state, authority_generation, valid_from, version,
    created_at, updated_at)
SELECT pg_catalog.uuidv7(), membership.deployment_id, 101, membership.principal_id, membership.id, 'it_admin',
    'active', 1, now() - INTERVAL '1 minute', 1, now() - INTERVAL '1 minute', now() - INTERVAL '1 minute'
FROM mesh.workspace_membership AS membership
WHERE membership.workspace_id = 101 AND membership.principal_id = $1 AND membership.state = 'active'`, newcomer)
	runInvitationFixture(ctx, t, admin, `UPDATE mesh.workspace_invitation SET role_key = 'network_admin'
WHERE public_id = $1::UUID`, "01890f00-0000-7000-8000-000000001974")
	refuse("an it_admin's network_admin invitation", "e7b", "late.joiner@example.test")
	runInvitationFixture(ctx, t, admin, `UPDATE mesh.workspace_invitation SET role_key = 'it_admin'
WHERE public_id = $1::UUID`, "01890f00-0000-7000-8000-000000001974")
	runInvitationFixture(ctx, t, admin, `UPDATE mesh.workspace_role_assignment SET state = 'revoked',
    revoked_at = now(), version = version + 1, updated_at = now()
WHERE workspace_id = 101 AND principal_id = $1 AND role_key = 'it_admin' AND state = 'active'`, newcomer)
	refuse("an invitation whose inviter lost the role", "e78", "late.joiner@example.test")
	runInvitationFixture(ctx, t, admin, `UPDATE mesh.workspace_role_assignment SET state = 'active',
    revoked_at = NULL, version = version + 1, updated_at = now()
WHERE workspace_id = 101 AND principal_id = $1 AND role_key = 'it_admin' AND state = 'revoked'`, newcomer)
	runInvitationFixture(ctx, t, admin, `UPDATE mesh.workspace_membership SET state = 'suspended'
WHERE workspace_id = 101 AND principal_id = $1 AND state = 'active'`, newcomer)
	refuse("an invitation whose inviter is suspended", "e7c", "late.joiner@example.test")
	runInvitationFixture(ctx, t, admin, `UPDATE mesh.workspace_membership SET state = 'active'
WHERE workspace_id = 101 AND principal_id = $1 AND state = 'suspended'`, newcomer)
	if _, err := accept("e79", "late.joiner@example.test"); err != nil {
		t.Fatalf("an it_admin's it_admin invitation: %v", err)
	}
	var lateRoles int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh.workspace_role_assignment AS assignment
JOIN mesh.workspace_invitation AS invitation ON invitation.accepted_by_principal_id = assignment.principal_id
WHERE invitation.public_id = $1::UUID AND assignment.role_key = 'it_admin' AND assignment.state = 'active'
  AND assignment.workspace_id = 101`, "01890f00-0000-7000-8000-000000001974").Scan(&lateRoles); err != nil ||
		lateRoles != 1 {
		t.Fatalf("the late joiner's it_admin roles = %d, %v", lateRoles, err)
	}
}

// runInvitationFixture changes invitation fixtures directly, past the
// triggers that guard their transitions.
func runInvitationFixture(ctx context.Context, t *testing.T, admin *pgx.Conn, sql string, args ...any) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `RESET ROLE; SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("invitation fixture: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// invitationAuthorityCounts counts every row an invitation acceptance can
// create, so a refused sign-in can be shown to create none.
type invitationAuthority struct {
	accounts, subjects, memberships, networkMemberships, roles, pending int64
}

func invitationAuthorityCounts(ctx context.Context, t *testing.T, admin *pgx.Conn) invitationAuthority {
	t.Helper()
	var counts invitationAuthority
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT count(*) FROM mesh.account),
    (SELECT count(*) FROM mesh.identity_subject),
    (SELECT count(*) FROM mesh.workspace_membership),
    (SELECT count(*) FROM mesh.network_membership),
    (SELECT count(*) FROM mesh.workspace_role_assignment),
    (SELECT count(*) FROM mesh.workspace_invitation WHERE state = 'pending')`).Scan(&counts.accounts,
		&counts.subjects, &counts.memberships, &counts.networkMemberships, &counts.roles,
		&counts.pending); err != nil {
		t.Fatal(err)
	}
	return counts
}

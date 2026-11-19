//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/core/internal/domain/workspace/roles"
)

// assertPostgreSQLWorkspaceRoles drives the schema 96 entry points through the
// production store: listing, assignment with replay, delegation ceiling,
// self-change, Network scope, revocation with replay, and audit evidence.
// Every assignment it creates is revoked before it returns.
func assertPostgreSQLWorkspaceRoles(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewWorkspaceRoleStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := roles.NewService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	// Principal 11 owns Workspace 103 for this test; principal 13 is a member.
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	member := authorityConfirmerAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	memberPrincipal := publicid.ID(member.PrincipalID())
	ownerPrincipal := publicid.ID(owner.PrincipalID())
	firstNetwork, err := network.ParseID("01890f00-0000-7000-8000-000000000203")
	if err != nil {
		t.Fatal(err)
	}
	auditBefore := countWorkspaceRoleAudit(ctx, t, admin)

	directory, err := service.ListMembers(ctx, roles.ListCommand{Session: owner, WorkspaceID: workspaceID})
	if err != nil || !directoryHasOwner(directory, ownerPrincipal) || !directoryHasMember(directory, memberPrincipal) {
		t.Fatalf("owner directory = %+v, error = %v", directory, err)
	}
	if _, err := service.ListMembers(ctx, roles.ListCommand{Session: member, WorkspaceID: workspaceID}); !errors.Is(err, roles.ErrForbidden) {
		t.Fatalf("plain member listed members: %v", err)
	}
	assertMemberDirectoryEmail(ctx, t, admin, service, owner, workspaceID, memberPrincipal, directory)

	itAdmin := newAssignCommand(t, owner, workspaceID, memberPrincipal, authorization.BuiltinRoleITAdmin, network.ID{})
	assigned, err := service.Assign(ctx, itAdmin)
	if err != nil || assigned.Replayed || assigned.Assignment.Version != 1 {
		t.Fatalf("owner assigned it_admin = %+v, error = %v", assigned, err)
	}
	replay, err := service.Assign(ctx, itAdmin)
	if err != nil || !replay.Replayed || replay.Assignment.ID != itAdmin.AssignmentID {
		t.Fatalf("assignment replay = %+v, error = %v", replay, err)
	}
	reused := itAdmin
	reused.Role = authorization.BuiltinRoleAuditor
	if _, err := service.Assign(ctx, reused); !errors.Is(err, roles.ErrConflict) {
		t.Fatalf("reused assignment ID for another role: %v", err)
	}
	if countWorkspaceRoleAudit(ctx, t, admin) != auditBefore+1 {
		t.Fatal("assignment and replay did not produce exactly one audit event")
	}

	// it_admin now reads members, but cannot exceed its ceiling or change itself.
	if _, err := service.ListMembers(ctx, roles.ListCommand{Session: member, WorkspaceID: workspaceID}); err != nil {
		t.Fatalf("it_admin cannot list members: %v", err)
	}
	if _, err := service.Assign(ctx, newAssignCommand(t, member, workspaceID, ownerPrincipal,
		authorization.BuiltinRoleAdmin, network.ID{})); !errors.Is(err, roles.ErrForbidden) {
		t.Fatalf("it_admin granted admin: %v", err)
	}
	if _, err := service.Assign(ctx, newAssignCommand(t, member, workspaceID, memberPrincipal,
		authorization.BuiltinRoleNetworkAdmin, network.ID{})); !errors.Is(err, roles.ErrForbidden) {
		t.Fatalf("member changed their own roles: %v", err)
	}
	if _, err := service.Assign(ctx, newAssignCommand(t, owner, workspaceID, ownerPrincipal,
		authorization.BuiltinRoleAuditor, network.ID{})); !errors.Is(err, roles.ErrForbidden) {
		t.Fatalf("owner assigned a role to themselves: %v", err)
	}

	scoped := newAssignCommand(t, owner, workspaceID, memberPrincipal, authorization.BuiltinRoleNetworkAdmin, firstNetwork)
	scopedResult, err := service.Assign(ctx, scoped)
	if err != nil || scopedResult.Assignment.NetworkID != firstNetwork {
		t.Fatalf("Network-scope network_admin = %+v, error = %v", scopedResult, err)
	}
	if _, err := service.Assign(ctx, newAssignCommand(t, owner, workspaceID, memberPrincipal,
		authorization.BuiltinRoleBillingAdmin, firstNetwork)); !errors.Is(err, roles.ErrInvalid) {
		t.Fatalf("billing_admin accepted Network scope: %v", err)
	}
	duplicate := newAssignCommand(t, owner, workspaceID, memberPrincipal, authorization.BuiltinRoleNetworkAdmin, firstNetwork)
	if _, err := service.Assign(ctx, duplicate); !errors.Is(err, roles.ErrConflict) {
		t.Fatalf("duplicate active role was accepted: %v", err)
	}
	if _, err := service.Revoke(ctx, newRevokeCommand(t, member, workspaceID, scoped.AssignmentID, 1)); !errors.Is(err, roles.ErrForbidden) {
		t.Fatalf("member revoked their own role: %v", err)
	}

	directory, err = service.ListMembers(ctx, roles.ListCommand{Session: owner, WorkspaceID: workspaceID})
	if err != nil || len(memberAssignments(directory, memberPrincipal)) != 2 {
		t.Fatalf("directory after assignments = %+v, error = %v", directory, err)
	}

	for _, id := range []publicid.ID{scoped.AssignmentID, itAdmin.AssignmentID} {
		revoke := newRevokeCommand(t, owner, workspaceID, id, 1)
		result, err := service.Revoke(ctx, revoke)
		if err != nil || result.Replayed || result.Version != 2 {
			t.Fatalf("revoke %s = %+v, error = %v", id, result, err)
		}
		replayed, err := service.Revoke(ctx, revoke)
		if err != nil || !replayed.Replayed {
			t.Fatalf("revoke replay %s = %+v, error = %v", id, replayed, err)
		}
	}
	if _, err := service.Revoke(ctx, newRevokeCommand(t, owner, workspaceID, itAdmin.AssignmentID, 3)); !errors.Is(err, roles.ErrConflict) {
		t.Fatalf("stale revocation did not conflict: %v", err)
	}
	if _, err := service.ListMembers(ctx, roles.ListCommand{Session: member, WorkspaceID: workspaceID}); !errors.Is(err, roles.ErrForbidden) {
		t.Fatalf("revoked it_admin still lists members: %v", err)
	}
	if countWorkspaceRoleAudit(ctx, t, admin) != auditBefore+4 {
		t.Fatal("each committed role change must produce exactly one audit event")
	}
}

func newAssignCommand(t *testing.T, session accountsession.Session, _ interface{ String() string },
	principal publicid.ID, role authorization.BuiltinRole, networkID network.ID) roles.AssignCommand {
	t.Helper()
	command := roles.AssignCommand{Session: session, PrincipalID: principal, Role: role, NetworkID: networkID}
	command.WorkspaceID, _ = session.LoginWorkspaceID()
	var err error
	if command.AssignmentID, err = publicid.New(); err != nil {
		t.Fatal(err)
	}
	if command.CorrelationID, err = publicid.New(); err != nil {
		t.Fatal(err)
	}
	return command
}

func newRevokeCommand(t *testing.T, session accountsession.Session, _ interface{ String() string },
	assignment publicid.ID, version int64) roles.RevokeCommand {
	t.Helper()
	command := roles.RevokeCommand{Session: session, AssignmentID: assignment, ExpectedVersion: version}
	command.WorkspaceID, _ = session.LoginWorkspaceID()
	var err error
	if command.CorrelationID, err = publicid.New(); err != nil {
		t.Fatal(err)
	}
	return command
}

func countWorkspaceRoleAudit(ctx context.Context, t *testing.T, admin *pgx.Conn) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind='workspace_role_assignment'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func directoryHasOwner(directory roles.Directory, principal publicid.ID) bool {
	for _, member := range directory.Members {
		if member.PrincipalID == principal {
			return member.Owner
		}
	}
	return false
}

func directoryHasMember(directory roles.Directory, principal publicid.ID) bool {
	for _, member := range directory.Members {
		if member.PrincipalID == principal && !member.Owner {
			return true
		}
	}
	return false
}

func memberAssignments(directory roles.Directory, principal publicid.ID) []roles.Assignment {
	for _, member := range directory.Members {
		if member.PrincipalID == principal {
			return member.Assignments
		}
	}
	return nil
}

// assertMemberDirectoryEmail checks schema 304: every member carries a join
// time, nobody has an email until Core stored a verified one, and a stored
// email shows on its own member only.
func assertMemberDirectoryEmail(ctx context.Context, t *testing.T, admin *pgx.Conn, service *roles.Service,
	owner accountsession.Session, workspaceID workspace.ID, memberPrincipal publicid.ID, directory roles.Directory) {
	t.Helper()
	// Later checks count rows; leave the fixture as it was.
	defer execFixtureWithoutTriggers(ctx, t, admin,
		`DELETE FROM mesh.account_email WHERE public_id = '01890f00-0000-7000-8000-0000000003a4'::UUID`)
	for _, listed := range directory.Members {
		if listed.JoinedAt.IsZero() {
			t.Fatalf("member %s has no join time", listed.PrincipalID)
		}
	}
	const email = "member-304@example.com"
	execFixtureWithoutTriggers(ctx, t, admin, `INSERT INTO mesh.account_email
		(public_id, deployment_id, account_id, email, verified_at, version, created_at, updated_at)
		SELECT '01890f00-0000-7000-8000-0000000003a4'::UUID, account.deployment_id, account.id, $2,
			pg_catalog.now(), 1, pg_catalog.now(), pg_catalog.now()
		FROM mesh.account AS account
		JOIN mesh.principal AS principal
		  ON principal.deployment_id = account.deployment_id AND principal.id = account.principal_id
		WHERE principal.public_id = $1`, memberPrincipal.String(), email)
	listed, err := service.ListMembers(ctx, roles.ListCommand{Session: owner, WorkspaceID: workspaceID})
	if err != nil {
		t.Fatalf("list members with an email: %v", err)
	}
	for _, entry := range listed.Members {
		switch {
		case entry.PrincipalID == memberPrincipal && entry.Email != email:
			t.Fatalf("member email = %q, want %q", entry.Email, email)
		case entry.PrincipalID != memberPrincipal && entry.Email == email:
			t.Fatalf("member %s shows another person's email", entry.PrincipalID)
		}
	}
}

// execFixtureWithoutTriggers writes one fixture row of an authority table
// with its triggers off: this read-path test needs a stored email, and the
// write path that appends its evidence (RecordEmail) is
// assertPostgreSQLAccountEmail's to prove.
func execFixtureWithoutTriggers(ctx context.Context, t *testing.T, admin *pgx.Conn, statement string, arguments ...any) {
	t.Helper()
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin fixture write: %v", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	if _, err := transaction.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatalf("turn triggers off: %v", err)
	}
	if tag, err := transaction.Exec(ctx, statement, arguments...); err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("fixture write %q: %d rows, %v", statement, tag.RowsAffected(), err)
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatalf("commit fixture write: %v", err)
	}
}

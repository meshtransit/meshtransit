//go:build integration

package integration

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/memberlifecycle"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/platform/config"
)

const (
	revocationPrincipalID = "01890f00-0000-7000-8000-000000009171"
	revocationAccountID   = "01890f00-0000-7000-8000-000000009172"
	revocationSubjectID   = "01890f00-0000-7000-8000-000000009173"
)

// revocationSessionIDs are the member's sessions: two signed in to Workspace
// 103, one signed in to no Workspace, and two issued later.
var revocationSessionIDs = [5]string{
	"01890f00-0000-7000-8000-000000009181", "01890f00-0000-7000-8000-000000009182",
	"01890f00-0000-7000-8000-000000009183", "01890f00-0000-7000-8000-000000009184",
	"01890f00-0000-7000-8000-000000009185",
}

// assertPostgreSQLAccountSessionRevocation qualifies schema 162 through the
// production stores with a member created for this check. An administrator
// ends only the member's sessions signed in to their Workspace and cannot
// target the owner or themselves; the person signs out everywhere from one
// session, which advances the generation and ends every session of the
// Account and nobody else's; the operator quarantines, which ends sessions
// and is refused by the resolvers, and releases. Each change has evidence.
func assertPostgreSQLAccountSessionRevocation(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, migrationConfig config.MigrationConfig) {
	t.Helper()
	options := postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second}
	memberStore, err := postgresadapter.NewMemberLifecycleStore(runtimePool, options)
	if err != nil {
		t.Fatal(err)
	}
	members, err := memberlifecycle.NewService(memberStore, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	logoutAll, err := postgresadapter.NewAccountSessionRevocationStore(runtimePool, options)
	if err != nil {
		t.Fatal(err)
	}
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	restore := seedRevocationMember(ctx, t, admin)
	defer restore()
	owner := managementRBACAccountSessionFixture(t)
	plain := authorityConfirmerAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	memberID, err := publicid.Parse(revocationPrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	revoke := func(session accountsession.Session, member publicid.ID) (memberlifecycle.Result, error) {
		return members.Change(ctx, session, memberlifecycle.Request{
			WorkspaceID: workspaceID, MemberID: member, Action: memberlifecycle.ActionRevokeSessions,
			Reason: "Integration check", CorrelationID: newCorrelationID(t),
		})
	}

	// An administrator: only the sessions signed in to their Workspace.
	if _, err := revoke(plain, memberID); !errors.Is(err, memberlifecycle.ErrForbidden) {
		t.Fatalf("plain member ended a member's sessions: %v", err)
	}
	if _, err := revoke(owner, publicid.ID(owner.PrincipalID())); !errors.Is(err, memberlifecycle.ErrProtected) {
		t.Fatalf("owner ended their own sessions as an administrator: %v", err)
	}
	revoked, err := revoke(owner, memberID)
	if err != nil || revoked.SessionsEnded != 2 || revoked.After.State != "active" ||
		revoked.After.Version != revoked.Before.Version {
		t.Fatalf("revoke sessions = %+v, %v", revoked, err)
	}
	for index, want := range []string{"administrative", "administrative", ""} {
		if reason := revocationSessionEndReason(ctx, t, admin, revocationSessionIDs[index]); reason != want {
			t.Fatalf("session %d end reason %q, want %q", index, reason, want)
		}
	}
	if generation, state := revocationAccount(ctx, t, admin); generation != 1 || state != "verified" {
		t.Fatalf("an administrator moved the Account: generation %d, %s", generation, state)
	}
	if count := countMemberRevocationAudit(ctx, t, admin, "workspace_membership", "member.sessions_revoked"); count != 1 {
		t.Fatalf("administrator revocation recorded %d events, want 1", count)
	}
	// Again, with no session left here: nothing ends and nothing is recorded.
	if again, err := revoke(owner, memberID); err != nil || again.SessionsEnded != 0 {
		t.Fatalf("revoke sessions with none left = %+v, %v", again, err)
	}
	if count := countMemberRevocationAudit(ctx, t, admin, "workspace_membership", "member.sessions_revoked"); count != 1 {
		t.Fatalf("revoking no session recorded an event (%d)", count)
	}

	// The person, from the session signed in to no Workspace: every session.
	insertRevocationSession(ctx, t, admin, 3, "103", 1)
	third := revocationSession(t, revocationSessionIDs[2], 1)
	// The Console renewed the session after it authenticated this request.
	revocationBypass(ctx, t, admin, []string{`UPDATE mesh.account_session SET version = 2
WHERE public_id = '` + revocationSessionIDs[2] + `'`})
	ended, err := logoutAll.RevokeAll(ctx, third, newCorrelationID(t))
	if err != nil || ended != 2 {
		t.Fatalf("sign out everywhere = %d, %v", ended, err)
	}
	for _, index := range []int{2, 3} {
		if reason := revocationSessionEndReason(ctx, t, admin, revocationSessionIDs[index]); reason != "logout_all" {
			t.Fatalf("session %d end reason %q after signing out everywhere", index, reason)
		}
	}
	if reason := revocationSessionEndReason(ctx, t, admin, integrationManagementSessionPublicID); reason != "" {
		t.Fatalf("signing out everywhere ended another Account's session: %q", reason)
	}
	if generation, _ := revocationAccount(ctx, t, admin); generation != 2 {
		t.Fatalf("signing out everywhere left generation %d, want 2", generation)
	}
	if count := countMemberRevocationAudit(ctx, t, admin, "account", "account.sessions_revoked"); count != 1 {
		t.Fatalf("signing out everywhere recorded %d events, want 1", count)
	}
	if _, err := logoutAll.RevokeAll(ctx, third, newCorrelationID(t)); !errors.Is(err,
		accountsession.ErrUnauthenticated) {
		t.Fatalf("an ended session signed out everywhere again: %v", err)
	}
	// A session still marked active but issued under the old generation has
	// no authority: the generation alone ends it.
	insertRevocationSession(ctx, t, admin, -1, "NULL", 1)
	if _, err := logoutAll.RevokeAll(ctx, revocationSession(t, "01890f00-0000-7000-8000-000000009186", 1),
		newCorrelationID(t)); !errors.Is(err, accountsession.ErrUnauthenticated) {
		t.Fatalf("a session of the old generation signed out everywhere: %v", err)
	}
	revocationBypass(ctx, t, admin, []string{`UPDATE mesh.account_session SET state = 'revoked', ended_at = now(),
    end_reason = 'administrative' WHERE public_id = '01890f00-0000-7000-8000-000000009186'`})

	// The operator: quarantine ends the new session, release restores login.
	operator := postgresadapter.MigrationOptions{
		Address: migrationConfig.PostgreSQL.Address, Database: migrationConfig.PostgreSQL.Database,
		User: migrationConfig.PostgreSQL.User, PasswordFile: migrationConfig.PostgreSQL.PasswordFile,
		CAFile: migrationConfig.PostgreSQL.CAFile, ConnectTimeout: migrationConfig.ConnectTimeout,
		LockTimeout: migrationConfig.LockTimeout, StatementTimeout: migrationConfig.StatementTimeout,
		Actor: migrationConfig.Actor, CodeRelease: "integration-test@local",
	}
	insertRevocationSession(ctx, t, admin, 4, "103", 2)
	if _, err := postgresadapter.ChangeAccountRecovery(ctx, operator, memberID,
		postgresadapter.AccountRelease); !errors.Is(err, postgresadapter.ErrAccountNotQuarantined) {
		t.Fatalf("released an Account that is not quarantined: %v", err)
	}
	quarantined, err := postgresadapter.ChangeAccountRecovery(ctx, operator, memberID, postgresadapter.AccountQuarantine)
	if err != nil || quarantined.SessionsEnded != 1 || quarantined.SessionGeneration != 3 ||
		quarantined.RecoveryState != "quarantined" {
		t.Fatalf("quarantine = %+v, %v", quarantined, err)
	}
	if reason := revocationSessionEndReason(ctx, t, admin, revocationSessionIDs[4]); reason != "account_suspended" {
		t.Fatalf("quarantine left the session %q", reason)
	}
	// A quarantined Account's session never resolves, even at its generation.
	insertRevocationSession(ctx, t, admin, -2, "103", 3)
	if _, err := logoutAll.RevokeAll(ctx, revocationSession(t, "01890f00-0000-7000-8000-000000009187", 3),
		newCorrelationID(t)); !errors.Is(err, accountsession.ErrUnauthenticated) {
		t.Fatalf("a quarantined Account's session signed out everywhere: %v", err)
	}
	if late, err := revoke(owner, memberID); err != nil || late.SessionsEnded != 1 {
		t.Fatalf("administrator revocation after quarantine = %+v, %v", late, err)
	}
	released, err := postgresadapter.ChangeAccountRecovery(ctx, operator, memberID, postgresadapter.AccountRelease)
	if err != nil || released.RecoveryState != "verified" || released.SessionGeneration != 3 {
		t.Fatalf("release = %+v, %v", released, err)
	}
	// Two signs-out everywhere at once, from two sessions: one ends both, the
	// other finds its session ended; neither deadlocks.
	for round := range 5 {
		generation := int64(3 + round)
		var sessions [2]accountsession.Session
		for index := range sessions {
			id := newPublicID(t).String()
			insertRevocationSessionID(ctx, t, admin, id, "NULL", generation)
			sessions[index] = revocationSession(t, id, generation)
		}
		results := make(chan error, 2)
		counts := make(chan int, 2)
		for _, session := range sessions {
			go func() {
				ended, err := logoutAll.RevokeAll(ctx, session, newCorrelationID(t))
				counts <- ended
				results <- err
			}()
		}
		var succeeded, refused, ended int
		for range 2 {
			err := <-results
			ended += <-counts
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, accountsession.ErrUnauthenticated):
				refused++
			default:
				t.Fatalf("round %d: concurrent sign-out everywhere failed: %v", round, err)
			}
		}
		if succeeded != 1 || refused != 1 || ended != 2 {
			t.Fatalf("round %d: %d succeeded, %d refused, %d ended", round, succeeded, refused, ended)
		}
	}
	unknown, err := publicid.Parse("01890f00-0000-7000-8000-000000009179")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postgresadapter.ChangeAccountRecovery(ctx, operator, unknown,
		postgresadapter.AccountRevokeSessions); !errors.Is(err, postgresadapter.ErrAccountNotFound) {
		t.Fatalf("unknown Account: %v", err)
	}
	var operatorActor string
	if err := admin.QueryRow(ctx, `SELECT payload ->> 'operator_actor' FROM mesh_audit.audit_event
WHERE target_kind = 'account' AND target_public_id = $1::UUID AND action = 'account.quarantined'`,
		revocationAccountID).Scan(&operatorActor); err != nil || operatorActor != migrationConfig.Actor {
		t.Fatalf("quarantine evidence names operator %q, want %q: %v", operatorActor, migrationConfig.Actor, err)
	}
	for action, want := range map[string]int64{"account.quarantined": 1, "account.released": 1} {
		if count := countMemberRevocationAudit(ctx, t, admin, "account", action); count != want {
			t.Fatalf("%s recorded %d events, want %d", action, count, want)
		}
	}

	var runtimeLogoutAll, runtimeRevoke, runtimeRecovery, workerLogoutAll bool
	if err := admin.QueryRow(ctx, `SELECT
    pg_catalog.has_function_privilege('mesh_runtime',
        'mesh_ops.logout_all_account_sessions_v1(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,uuid)', 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_runtime',
        'mesh_ops.revoke_workspace_member_sessions_v1(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,uuid,uuid,uuid,timestamptz)',
        'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_runtime', 'mesh_ops.change_account_recovery_v1(uuid,text,uuid)', 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_worker',
        'mesh_ops.logout_all_account_sessions_v1(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,uuid)', 'EXECUTE')`).Scan(
		&runtimeLogoutAll, &runtimeRevoke, &runtimeRecovery, &workerLogoutAll); err != nil {
		t.Fatal(err)
	}
	if !runtimeLogoutAll || !runtimeRevoke || runtimeRecovery || workerLogoutAll {
		t.Fatalf("privileges: runtime logout-all %t, revoke %t, recovery %t; worker logout-all %t",
			runtimeLogoutAll, runtimeRevoke, runtimeRecovery, workerLogoutAll)
	}
}

// revocationSession is the member's session as the resolver issued it.
func revocationSession(t *testing.T, id string, generation int64) accountsession.Session {
	t.Helper()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	principalID, err := identity.ParsePrincipalID(revocationPrincipalID)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, err := accountsession.ParseID(id)
	if err != nil {
		t.Fatal(err)
	}
	subjectID, err := accountsession.ParseIdentitySubjectID(revocationSubjectID)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID, IdentitySubjectID: subjectID,
		AuthenticationTime: now.Add(-time.Minute), ACR: "urn:meshtransit:assurance:mfa", AMR: []string{"pwd", "mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: generation,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(20 * time.Minute), AbsoluteExpiresAt: now.Add(7 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

// seedRevocationMember adds an account member to Workspace 103 with three
// active sessions (two signed in to 103, one to no Workspace) and returns the
// function that revokes the membership. Triggers are bypassed only for this
// fixture, never for the code under test.
func seedRevocationMember(ctx context.Context, t *testing.T, admin *pgx.Conn) func() {
	t.Helper()
	revocationBypass(ctx, t, admin, []string{
		`INSERT INTO mesh.principal (id, public_id, deployment_id, kind, state) OVERRIDING SYSTEM VALUE
VALUES (9171, '` + revocationPrincipalID + `', 1, 'account', 'active')`,
		`INSERT INTO mesh.account (id, public_id, deployment_id, principal_id, display_name, session_generation, recovery_state)
OVERRIDING SYSTEM VALUE VALUES (9172, '` + revocationAccountID + `', 1, 9171, 'Revocation Member', 1, 'verified')`,
		`INSERT INTO mesh.identity_subject (id, public_id, deployment_id, identity_provider_id, principal_id,
    subject_digest_algorithm, subject_digest_key_id, subject_digest, claims_revision, last_seen_at, state)
OVERRIDING SYSTEM VALUE VALUES (9173, '` + revocationSubjectID + `', 1, 601, 9171, 'hmac-sha256-v1',
    'integration-v1', pg_catalog.decode(pg_catalog.repeat('c3', 32), 'hex'), 1, now(), 'active')`,
		`INSERT INTO mesh.workspace_membership (id, public_id, deployment_id, workspace_id, principal_id, state,
    authority_generation, valid_from) OVERRIDING SYSTEM VALUE
VALUES (9174, '01890f00-0000-7000-8000-000000009174', 1, 103, 9171, 'active', 1, now() - INTERVAL '1 minute')`,
	})
	insertRevocationSession(ctx, t, admin, 0, "103", 1)
	insertRevocationSession(ctx, t, admin, 1, "103", 1)
	insertRevocationSession(ctx, t, admin, 2, "NULL", 1)
	return func() {
		revocationBypass(ctx, t, admin, []string{
			`UPDATE mesh.workspace_membership SET state = 'revoked' WHERE id = 9174`,
			`UPDATE mesh.account_session SET state = 'revoked', ended_at = now(), end_reason = 'administrative'
WHERE principal_id = 9171 AND state = 'active'`,
		})
	}
}

// insertRevocationSession adds one active session of the member, with the
// index into revocationSessionIDs, or one of two spare IDs for -1 and -2.
func insertRevocationSession(ctx context.Context, t *testing.T, admin *pgx.Conn, index int, workspace string,
	generation int64) {
	t.Helper()
	id := "01890f00-0000-7000-8000-000000009186"
	if index == -2 {
		id = "01890f00-0000-7000-8000-000000009187"
	}
	if index >= 0 {
		id = revocationSessionIDs[index]
	}
	insertRevocationSessionID(ctx, t, admin, id, workspace, generation)
}

// insertRevocationSessionID adds one active session of the member with this ID.
func insertRevocationSessionID(ctx context.Context, t *testing.T, admin *pgx.Conn, id, workspace string,
	generation int64) {
	t.Helper()
	revocationBypass(ctx, t, admin, []string{`INSERT INTO mesh.account_session (
    public_id, deployment_id, principal_id, identity_provider_id, identity_subject_id, identity_provider_client_id,
    login_workspace_id, token_digest_algorithm, token_digest_key_id, token_digest, provider_generation,
    authentication_time, acr, amr, principal_authority_generation, account_session_generation,
    deployment_recovery_epoch, issued_at, last_used_at, idle_expires_at, absolute_expires_at, state
) VALUES (
    '` + id + `', 1, 9171, 601, 9173, 621, ` + workspace + `, 'hmac-sha256-v1', 'integration-v1',
    pg_catalog.sha256(pg_catalog.convert_to('` + id + `', 'UTF8')), 1, now() - INTERVAL '1 minute',
    'urn:meshtransit:assurance:mfa', ARRAY['pwd', 'mfa'], 1, ` + strconv.FormatInt(generation, 10) + `, 1,
    now(), now(), now() + INTERVAL '30 minutes', now() + INTERVAL '8 hours', 'active')`})
}

func revocationBypass(ctx context.Context, t *testing.T, admin *pgx.Conn, statements []string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `RESET ROLE; SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	for _, statement := range statements {
		if _, err := tx.Exec(ctx, statement); err != nil {
			t.Fatalf("revocation fixture: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func revocationSessionEndReason(ctx context.Context, t *testing.T, admin *pgx.Conn, id string) string {
	t.Helper()
	var reason *string
	if err := admin.QueryRow(ctx, `SELECT end_reason FROM mesh.account_session WHERE public_id = $1::UUID`,
		id).Scan(&reason); err != nil {
		t.Fatal(err)
	}
	if reason == nil {
		return ""
	}
	return *reason
}

func revocationAccount(ctx context.Context, t *testing.T, admin *pgx.Conn) (int64, string) {
	t.Helper()
	var generation int64
	var state string
	if err := admin.QueryRow(ctx, `SELECT session_generation, recovery_state FROM mesh.account WHERE id = 9172`).Scan(
		&generation, &state); err != nil {
		t.Fatal(err)
	}
	return generation, state
}

func countMemberRevocationAudit(ctx context.Context, t *testing.T, admin *pgx.Conn, kind, action string) int64 {
	t.Helper()
	target := revocationPrincipalID
	if kind == "account" {
		target = revocationAccountID
	}
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind = $1 AND target_public_id = $2::UUID AND action = $3`, kind, target, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

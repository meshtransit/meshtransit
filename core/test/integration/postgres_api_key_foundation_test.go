//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/identity/accountsession"
)

const (
	// apiKeyFoundationSessionID is a key bound to the Workspace of the probed
	// Network; apiKeyElsewhereSessionID one bound to another Workspace of the
	// same person; humanTwinSessionID an interactive copy that has not idled
	// out, the baseline a key must match in its own Workspace.
	apiKeyFoundationSessionID = "01890f00-0000-7000-8000-00000000a7a1"
	apiKeyElsewhereSessionID  = "01890f00-0000-7000-8000-00000000a7b1"
	humanTwinSessionID        = "01890f00-0000-7000-8000-00000000a7c1"
)

// apiKeyProbe is a human Session and a Network where it holds a permission
// on the key allowlist (read) and one that is not (write).
type apiKeyProbe struct {
	session, workspace, network, read, write string
}

// assertPostgreSQLAPIKeyFoundation drives schema 320 (V1-80 A1): a key's
// Session row resolves permissions only in its own Workspace and only for
// permissions on mesh.api_key_permission, the human Session it was copied
// from keeps resolving everywhere, checks that admit only active Sessions
// refuse the key, and the row is write-once until it ends.
func assertPostgreSQLAPIKeyFoundation(ctx context.Context, t *testing.T, admin *pgx.Conn, owner accountsession.Session) {
	t.Helper()
	// The owner of a Workspace with an active Network holds every Network
	// permission there once a member: device.read is on the key allowlist,
	// device.manage is not.
	probe := apiKeyProbe{session: owner.ID().String(), read: "device.read", write: "device.manage"}
	if err := admin.QueryRow(ctx, `SELECT workspace.public_id::TEXT, network.public_id::TEXT
FROM mesh.account_session AS session
JOIN mesh.workspace AS workspace ON workspace.owner_principal_id = session.principal_id AND workspace.state = 'active'
JOIN mesh.network AS network ON network.workspace_id = workspace.id AND network.state = 'active'
WHERE session.public_id = $1::UUID ORDER BY 1, 2 LIMIT 1`, probe.session).Scan(&probe.workspace, &probe.network); err != nil {
		t.Fatalf("a Workspace the owner owns with an active Network: %v", err)
	}
	ensureOwnerMembership(ctx, t, admin, probe.session, probe.workspace)
	var elsewhere string
	if err := admin.QueryRow(ctx, `SELECT workspace.public_id::TEXT
FROM mesh.account_session AS session
JOIN mesh.workspace AS workspace ON workspace.deployment_id = session.deployment_id
WHERE session.public_id = $1::UUID AND workspace.public_id <> $2::UUID
ORDER BY EXISTS (SELECT 1 FROM mesh.workspace_membership AS membership
    WHERE membership.workspace_id = workspace.id AND membership.principal_id = session.principal_id
      AND membership.state = 'active') DESC, 1
LIMIT 1`, probe.session, probe.workspace).Scan(&elsewhere); err != nil {
		t.Fatalf("a second Workspace: %v", err)
	}
	copySessionAsAPIKey(ctx, t, admin, probe.session, humanTwinSessionID, probe.workspace, "a7c1", "interactive", false)
	copySessionAsAPIKey(ctx, t, admin, probe.session, apiKeyFoundationSessionID, probe.workspace, "a7a1", "api_key", true)
	copySessionAsAPIKey(ctx, t, admin, probe.session, apiKeyElsewhereSessionID, elsewhere, "a7b1", "api_key", false)

	networkWith := func(resolver, session, workspaceID, networkID, permission string) int {
		t.Helper()
		var grant []removalFixtureStatement
		if resolver == "resolve_network_permission_v1" {
			grant = networkRoleBindingFixture(probe)
		}
		return scopedCount(ctx, t, admin, grant, workspaceID, networkID, `
SELECT count(*) FROM mesh.account_session AS session
JOIN mesh.deployment AS deployment ON deployment.id = session.deployment_id
JOIN mesh.principal AS principal ON principal.id = session.principal_id
JOIN mesh.identity_subject AS subject ON subject.id = session.identity_subject_id
CROSS JOIN LATERAL mesh_ops.`+resolver+`(
    session.public_id, deployment.installation_public_id, principal.public_id, subject.public_id,
    session.version, session.principal_authority_generation, session.account_session_generation,
    session.provider_generation, session.deployment_recovery_epoch,
    $2::UUID, $3::UUID, $4, pg_catalog.transaction_timestamp()) AS resolved
WHERE session.public_id = $1::UUID`, session, workspaceID, networkID, permission)
	}
	network := func(session, workspaceID, networkID, permission string) int {
		t.Helper()
		return networkWith("resolve_network_permission_v2", session, workspaceID, networkID, permission)
	}
	workspaceScoped := func(session, workspaceID string) int {
		t.Helper()
		return scopedCount(ctx, t, admin, nil, workspaceID, "", `
SELECT count(*) FROM mesh.account_session AS session
JOIN mesh.deployment AS deployment ON deployment.id = session.deployment_id
JOIN mesh.principal AS principal ON principal.id = session.principal_id
JOIN mesh.identity_subject AS subject ON subject.id = session.identity_subject_id
CROSS JOIN LATERAL mesh_ops.resolve_workspace_permission_v1(
    session.public_id, deployment.installation_public_id, principal.public_id, subject.public_id,
    session.version, session.principal_authority_generation, session.account_session_generation,
    session.provider_generation, session.deployment_recovery_epoch,
    $2::UUID, 'member.read', pg_catalog.transaction_timestamp()) AS resolved
WHERE session.public_id = $1::UUID`, session, workspaceID)
	}

	human := humanTwinSessionID
	if network(human, probe.workspace, probe.network, probe.read) != 1 ||
		network(human, probe.workspace, probe.network, probe.write) != 1 {
		t.Fatalf("baseline: the human twin lost the probed permissions %+v", probe)
	}
	if got := network(apiKeyFoundationSessionID, probe.workspace, probe.network, probe.read); got != 1 {
		t.Errorf("key lacks %s on a Network of its own Workspace: %d", probe.read, got)
	}
	if got := network(apiKeyFoundationSessionID, probe.workspace, probe.network, probe.write); got != 0 {
		t.Errorf("key resolved %s, which is not on mesh.api_key_permission: %d", probe.write, got)
	}
	if got := network(apiKeyElsewhereSessionID, probe.workspace, probe.network, probe.read); got != 0 {
		t.Errorf("key bound to %s reached a Network of %s", elsewhere, probe.workspace)
	}
	// resolve_network_permission_v1 reads Network role bindings only; with a
	// rollback-only binding of both permissions to the person, a key matches
	// the human there for read, never for write or outside its Workspace.
	for _, permission := range []string{probe.read, probe.write} {
		if baseline := networkWith("resolve_network_permission_v1", human, probe.workspace, probe.network, permission); baseline != 1 {
			t.Fatalf("baseline: v1 %s through the fixture binding: %d", permission, baseline)
		}
		want := 1
		if permission == probe.write {
			want = 0
		}
		if got := networkWith("resolve_network_permission_v1", apiKeyFoundationSessionID, probe.workspace, probe.network, permission); got != want {
			t.Errorf("v1 %s: key %d, want %d", permission, got, want)
		}
		if got := networkWith("resolve_network_permission_v1", apiKeyElsewhereSessionID, probe.workspace, probe.network, permission); got != 0 {
			t.Errorf("v1 %s: key bound to %s reached %s: %d", permission, elsewhere, probe.workspace, got)
		}
	}
	if got := workspaceScoped(human, probe.workspace); got != 1 {
		t.Fatalf("baseline: the human twin lacks member.read in %s: %d", probe.workspace, got)
	}
	for _, workspaceID := range []string{probe.workspace, elsewhere} {
		baseline := workspaceScoped(human, workspaceID)
		if baseline == 0 {
			t.Logf("member.read: the person holds nothing in %s, so only the refusals there are checked", workspaceID)
		}
		for key, bound := range map[string]string{apiKeyFoundationSessionID: probe.workspace, apiKeyElsewhereSessionID: elsewhere} {
			want := 0
			if bound == workspaceID {
				want = baseline
			}
			if got := workspaceScoped(key, workspaceID); got != want {
				t.Errorf("key bound to %s, member.read in %s: %d, want %d (human %d)", bound, workspaceID, got, want, baseline)
			}
		}
	}

	// Checks that admit only active Sessions refuse the key; the twin is the
	// positive control.
	accountSession := func(session string) int {
		t.Helper()
		return scopedCount(ctx, t, admin, nil, probe.workspace, "", `SELECT count(*) FROM mesh.account_session AS session
JOIN mesh.deployment AS deployment ON deployment.id = session.deployment_id
JOIN mesh.principal AS principal ON principal.id = session.principal_id
JOIN mesh.identity_subject AS subject ON subject.id = session.identity_subject_id
CROSS JOIN LATERAL mesh_ops.resolve_account_session_v1(
    session.public_id, deployment.installation_public_id, principal.public_id, subject.public_id,
    session.version, session.principal_authority_generation, session.account_session_generation,
    session.provider_generation, session.deployment_recovery_epoch, pg_catalog.transaction_timestamp()) AS resolved
WHERE session.public_id = $1::UUID`, session)
	}
	if got := accountSession(human); got != 1 {
		t.Fatalf("baseline: resolve_account_session_v1 refused the human twin: %d", got)
	}
	if got := accountSession(apiKeyFoundationSessionID); got != 0 {
		t.Errorf("resolve_account_session_v1 admitted a key (%d rows)", got)
	}

	// Write-once, each change attempted inside a valid change context so only
	// the transition trigger can refuse it.
	for name, change := range map[string]struct{ statement, message string }{
		"touch": {`UPDATE mesh.account_session SET last_used_at = last_used_at + interval '1 second',
    version = version + 1, updated_at = pg_catalog.clock_timestamp() WHERE public_id = $1::UUID`,
			"invalid account session state transition"},
		"rebind": {`UPDATE mesh.account_session SET login_workspace_id = (SELECT id FROM mesh.workspace
    WHERE public_id = $2::UUID), version = version + 1, updated_at = pg_catalog.clock_timestamp()
WHERE public_id = $1::UUID`, "account session binding is immutable"},
		"kind": {`UPDATE mesh.account_session SET kind = 'interactive', version = version + 1,
    updated_at = pg_catalog.clock_timestamp() WHERE public_id = $1::UUID`, "account session binding is immutable"},
		"reactivate": {`UPDATE mesh.account_session SET state = 'active', version = version + 1,
    updated_at = pg_catalog.clock_timestamp() WHERE public_id = $1::UUID`, "invalid account session state transition"},
		// Ending is allowed, but not together with a touch of the times.
		"revoke and touch": {`UPDATE mesh.account_session SET state = 'revoked', ended_at = pg_catalog.clock_timestamp(),
    end_reason = 'api_key_revoked', last_used_at = last_used_at + interval '1 second', version = version + 1,
    updated_at = pg_catalog.clock_timestamp() WHERE public_id = $1::UUID`, "invalid account session state transition"},
		"revoke and extend": {`UPDATE mesh.account_session SET state = 'revoked', ended_at = pg_catalog.clock_timestamp(),
    end_reason = 'api_key_revoked', idle_expires_at = idle_expires_at + interval '1 second', version = version + 1,
    updated_at = pg_catalog.clock_timestamp() WHERE public_id = $1::UUID`, "invalid account session state transition"},
	} {
		expectSessionChangeRefused(ctx, t, admin, name, change.statement, change.message,
			apiKeyFoundationSessionID, elsewhere)
	}
	expectSessionChangeRefused(ctx, t, admin, "human to api_key", `UPDATE mesh.account_session SET state = 'api_key',
    version = version + 1, updated_at = pg_catalog.clock_timestamp() WHERE public_id = $1::UUID`,
		"invalid account session state transition", humanTwinSessionID, elsewhere)

	// Ending is the one change; then the key resolves nothing. The other two
	// rows end too: later steps count the person's Sessions.
	for _, row := range []struct{ id, suffix, reason string }{
		{apiKeyFoundationSessionID, "a7a2", "api_key_revoked"},
		{apiKeyElsewhereSessionID, "a7b2", "api_key_revoked"},
		{humanTwinSessionID, "a7c2", "administrative"},
	} {
		commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
			changePublicID: "01890f01-0000-7000-8000-00000000" + row.suffix, eventPublicID: "01890f02-0000-7000-8000-00000000" + row.suffix,
			outboxPublicID: "01890f03-0000-7000-8000-00000000" + row.suffix, streamID: 1, aggregateKind: "account_session",
			aggregatePublicID: row.id, aggregateVersion: 2,
			action: "account_session.revoked", permission: "identity.session", outboxEventClass: "identity.account_session.revoked",
		}, func(transaction pgx.Tx) {
			if _, err := transaction.Exec(ctx, `UPDATE mesh.account_session SET state = 'revoked',
    ended_at = pg_catalog.clock_timestamp(), end_reason = $2, version = version + 1,
    updated_at = pg_catalog.clock_timestamp() WHERE public_id = $1::UUID`, row.id, row.reason); err != nil {
				t.Fatalf("end %s: %v", row.id, err)
			}
		})
	}
	if got := network(apiKeyFoundationSessionID, probe.workspace, probe.network, probe.read); got != 0 {
		t.Errorf("revoked key still resolves: %d", got)
	}
}

// ensureOwnerMembership gives the owner an active membership in the
// Workspace when it has none (the owner branch of the resolver needs one).
func ensureOwnerMembership(ctx context.Context, t *testing.T, admin *pgx.Conn, session, workspacePublicID string) {
	t.Helper()
	var present bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mesh.account_session AS session
JOIN mesh.workspace AS workspace ON workspace.public_id = $2::UUID
JOIN mesh.workspace_membership AS membership
  ON membership.workspace_id = workspace.id AND membership.principal_id = session.principal_id
 AND membership.state = 'active'
WHERE session.public_id = $1::UUID)`, session, workspacePublicID).Scan(&present); err != nil {
		t.Fatal(err)
	}
	if present {
		return
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: "01890f01-0000-7000-8000-00000000a7d1", eventPublicID: "01890f02-0000-7000-8000-00000000a7d1",
		outboxPublicID: "01890f03-0000-7000-8000-00000000a7d1", streamID: 1, aggregateKind: "workspace_membership",
		aggregatePublicID: "01890f00-0000-7000-8000-00000000a7d1", aggregateVersion: 1,
		action: "workspace_membership.created", permission: "system.bootstrap", outboxEventClass: "workspace_membership.created",
	}, func(transaction pgx.Tx) {
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.workspace_membership (
    public_id, deployment_id, workspace_id, principal_id, state, authority_generation, valid_from)
SELECT '01890f00-0000-7000-8000-00000000a7d1'::UUID, session.deployment_id, workspace.id, session.principal_id,
    'active', 1, pg_catalog.transaction_timestamp() - interval '1 minute'
FROM mesh.account_session AS session JOIN mesh.workspace AS workspace ON workspace.public_id = $2::UUID
WHERE session.public_id = $1::UUID`, session, workspacePublicID); err != nil {
			t.Fatalf("owner membership: %v", err)
		}
	})
}

// copySessionAsAPIKey inserts a row from the source Session: its identity
// with the current generations of its Principal, Account, provider and
// Deployment (the source may have ended in an earlier step), fresh times,
// no idle expiry, kind and state as asked (api_key/api_key or
// interactive/active), bound to workspacePublicID ("" keeps the source's
// login Workspace). checkStart also proves an interactive row cannot start
// in the api_key state.
func copySessionAsAPIKey(ctx context.Context, t *testing.T, admin *pgx.Conn,
	source, sessionID, workspacePublicID, suffix, kind string, checkStart bool,
) {
	t.Helper()
	state := "api_key"
	if kind == "interactive" {
		state = "active"
	}
	insert := func(transaction pgx.Tx, kind, state string) error {
		_, err := transaction.Exec(ctx, `INSERT INTO mesh.account_session (`+apiKeySessionColumns+`)
SELECT $1::UUID, session.deployment_id, session.principal_id, session.identity_provider_id,
    session.identity_subject_id, session.identity_provider_client_id,
    COALESCE((SELECT id FROM mesh.workspace WHERE public_id = NULLIF($3, '')::UUID), session.login_workspace_id),
    session.token_digest_algorithm, session.token_digest_key_id,
    pg_catalog.sha256(pg_catalog.convert_to($1::TEXT, 'UTF8')),
    provider.current_generation, now.at - interval '1 minute', session.acr, session.amr,
    principal.authority_generation, account.session_generation, deployment.recovery_epoch,
    now.at - interval '1 minute', now.at - interval '1 minute', now.at + interval '1 hour',
    now.at + interval '1 hour', $5, $4, now.at - interval '1 minute', now.at - interval '1 minute'
FROM mesh.account_session AS session
JOIN mesh.deployment AS deployment ON deployment.id = session.deployment_id
JOIN mesh.principal AS principal ON principal.id = session.principal_id
JOIN mesh.account AS account ON account.principal_id = session.principal_id
JOIN mesh.identity_provider AS provider ON provider.id = session.identity_provider_id
CROSS JOIN (SELECT pg_catalog.transaction_timestamp() AS at) AS now
WHERE session.public_id = $2::UUID`, sessionID, source, workspacePublicID, kind, state)
		return err
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: "01890f01-0000-7000-8000-00000000" + suffix, eventPublicID: "01890f02-0000-7000-8000-00000000" + suffix,
		outboxPublicID: "01890f03-0000-7000-8000-00000000" + suffix, streamID: 1, aggregateKind: "account_session",
		aggregatePublicID: sessionID, aggregateVersion: 1,
		action: "account_session.issued", permission: "identity.session", outboxEventClass: "identity.account_session.issued",
	}, func(transaction pgx.Tx) {
		if checkStart {
			if _, err := transaction.Exec(ctx, `SAVEPOINT wrong_kind`); err != nil {
				t.Fatal(err)
			}
			// Neither an interactive row in the key state nor a key in the
			// active state, which every legacy check would admit, can start.
			for _, wrong := range []struct{ kind, state string }{{"interactive", "api_key"}, {"api_key", "active"}} {
				err := insert(transaction, wrong.kind, wrong.state)
				postgresError, ok := errors.AsType[*pgconn.PgError](err)
				if !ok || postgresError.Code != "23514" || postgresError.Message != "invalid initial human authentication state" {
					t.Errorf("a %s row starting as %s: got %v, want the transition trigger's refusal", wrong.kind, wrong.state, err)
				}
				if _, err := transaction.Exec(ctx, `ROLLBACK TO SAVEPOINT wrong_kind`); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := insert(transaction, kind, state); err != nil {
			t.Fatalf("insert %s Session row: %v", kind, err)
		}
	})
}

const apiKeySessionColumns = `public_id, deployment_id, principal_id, identity_provider_id, identity_subject_id,
    identity_provider_client_id, login_workspace_id, token_digest_algorithm, token_digest_key_id, token_digest,
    provider_generation, authentication_time, acr, amr, principal_authority_generation, account_session_generation,
    deployment_recovery_epoch, issued_at, last_used_at, idle_expires_at, absolute_expires_at, state, kind,
    created_at, updated_at`

// expectSessionChangeRefused runs one change of a Session row inside a
// change context, so the audit trigger accepts it and only the transition
// trigger can refuse it, and checks the refusal's message. The transaction
// is rolled back.
func expectSessionChangeRefused(ctx context.Context, t *testing.T, admin *pgx.Conn, name, statement, message string,
	sessionID, otherWorkspace string,
) {
	t.Helper()
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	setIntegrationChange(ctx, t, transaction, "01890f01-0000-7000-8000-00000000a7f1")
	args := []any{sessionID}
	if name == "rebind" {
		args = append(args, otherWorkspace)
	}
	_, err = transaction.Exec(ctx, statement, args...)
	postgresError, ok := errors.AsType[*pgconn.PgError](err)
	if !ok || postgresError.Code != "23514" || postgresError.Message != message {
		t.Errorf("%s: got %v, want 23514 %q", name, err, message)
	}
}

// scopedCount runs a resolver probe the way Core does: inside a transaction
// that names the requested Workspace and Network, which the forced row-level
// security on mesh.workspace and mesh.network requires. Setup rows are
// written with triggers off first. It rolls back, so nothing stays.
func scopedCount(ctx context.Context, t *testing.T, admin *pgx.Conn, setup []removalFixtureStatement,
	workspaceID, networkID, query string, args ...any,
) int {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin resolver probe: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if len(setup) > 0 {
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			t.Fatal(err)
		}
		for _, statement := range setup {
			if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
				t.Fatalf("resolver probe setup: %v", err)
			}
		}
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = origin`); err != nil {
			t.Fatal(err)
		}
	}
	// The resolvers lock the Workspace and Network rows, so the row-level
	// security UPDATE policies apply too: they read the internal scope.
	var workspaceInternal, networkInternal string
	if err := tx.QueryRow(ctx, `SELECT
    COALESCE((SELECT workspace.id::TEXT FROM mesh.workspace AS workspace WHERE workspace.public_id = $1::UUID), ''),
    COALESCE((SELECT network.id::TEXT FROM mesh.network AS network WHERE network.public_id = NULLIF($2, '')::UUID), '')`,
		workspaceID, networkID).Scan(&workspaceInternal, &networkInternal); err != nil {
		t.Fatalf("resolve the resolver probe scope: %v", err)
	}
	if workspaceInternal == "" || (networkID != "" && networkInternal == "") {
		t.Fatalf("resolver probe scope %s/%s does not exist", workspaceID, networkID)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.requested_workspace_public_id', $1, TRUE),
    pg_catalog.set_config('mesh.requested_network_public_id', $2, TRUE),
    pg_catalog.set_config('mesh.workspace_id', $3, TRUE),
    pg_catalog.set_config('mesh.network_id', $4, TRUE)`, workspaceID, networkID, workspaceInternal, networkInternal); err != nil {
		t.Fatalf("name the resolver probe scope: %v", err)
	}
	var count int
	if err := tx.QueryRow(ctx, query, args...).Scan(&count); err != nil {
		t.Fatalf("resolver probe: %v", err)
	}
	return count
}

// networkRoleBindingFixture binds a custom role holding the probe's read and
// write permissions to the person on the probed Network, for one rollback-only
// probe of resolve_network_permission_v1.
func networkRoleBindingFixture(probe apiKeyProbe) []removalFixtureStatement {
	const id = 970320
	return []removalFixtureStatement{
		{sql: `INSERT INTO mesh.role_definition (id, public_id, deployment_id, workspace_id, role_key, display_name,
    kind, state, authority_generation)
OVERRIDING SYSTEM VALUE SELECT $1::BIGINT, pg_catalog.uuidv7(), workspace.deployment_id, workspace.id,
    'api_key_probe', 'API key probe', 'custom', 'active', 1
FROM mesh.workspace AS workspace WHERE workspace.public_id = $2::UUID`, args: []any{id, probe.workspace}},
		{sql: `INSERT INTO mesh.role_permission (public_id, deployment_id, workspace_id, role_definition_id, permission_id)
SELECT pg_catalog.uuidv7(), role.deployment_id, role.workspace_id, role.id, permission.id
FROM mesh.role_definition AS role JOIN mesh.permission AS permission ON permission.permission_key IN ($2, $3)
WHERE role.id = $1::BIGINT`, args: []any{id, probe.read, probe.write}},
		{sql: `INSERT INTO mesh.role_binding (id, public_id, deployment_id, workspace_id, network_id, principal_id,
    workspace_membership_id, role_definition_id, state, authority_generation, valid_from)
OVERRIDING SYSTEM VALUE SELECT $1::BIGINT, pg_catalog.uuidv7(), membership.deployment_id, membership.workspace_id,
    network.id, membership.principal_id, membership.id, $1::BIGINT, 'active', 1,
    pg_catalog.transaction_timestamp() - INTERVAL '1 minute'
FROM mesh.account_session AS session
JOIN mesh.workspace AS workspace ON workspace.public_id = $2::UUID
JOIN mesh.network AS network ON network.workspace_id = workspace.id AND network.public_id = $3::UUID
JOIN mesh.workspace_membership AS membership
  ON membership.workspace_id = workspace.id AND membership.principal_id = session.principal_id
 AND membership.state = 'active'
WHERE session.public_id = $4::UUID`, args: []any{id, probe.workspace, probe.network, probe.session}},
	}
}

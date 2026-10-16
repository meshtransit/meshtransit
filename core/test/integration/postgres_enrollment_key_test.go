//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/enrollmentkey"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
)

func newIntegrationEnrollmentKeyService(t *testing.T, runtimePool *postgresadapter.Pool) *enrollmentkey.Service {
	t.Helper()
	keyID, err := enrollment.NewDigestKeyID("integration-enrollment-key-v1")
	if err != nil {
		t.Fatal(err)
	}
	material := filledIntegrationKey(0x61)
	digestKey, err := enrollment.NewDigestKey(keyID, material[:])
	if err != nil {
		t.Fatal(err)
	}
	keyring, err := enrollment.NewCredentialKeyring(digestKey)
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgresadapter.NewEnrollmentKeyStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second},
		keyring)
	if err != nil {
		t.Fatal(err)
	}
	service, err := enrollmentkey.NewService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// assertPostgreSQLEnrollmentKeys qualifies enrollment keys through the
// production store on Network 203: a key enrolls one Device, the person who
// creates it picks the Device's lifetime (including never) and the key's own
// validity (24 hours by default) separately; only digests are stored; the
// key is revealed once; list never returns it; a custom role without the
// permission and network_admin cannot issue or revoke, admin and it_admin
// can; every creation and revocation is one event on the Network stream
// with the lifetimes chosen.
func assertPostgreSQLEnrollmentKeys(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	service := newIntegrationEnrollmentKeyService(t, runtimePool)
	members := newNetworkMemberFixture(t, runtimePool)
	custom, confirmer := members.owner, members.confirmer

	// The fixture's custom role manages Network members but not keys.
	if _, err := service.Issue(ctx, custom, enrollmentkey.IssueRequest{
		Scope: members.scope, DeviceLifetime: enrollment.NeverExpiringDeviceLifetime(),
		CorrelationID: newCorrelationID(t),
	}); !errors.Is(err, enrollmentkey.ErrForbidden) {
		t.Fatalf("a role without enrollment_credential.issue issued a key: %v", err)
	}
	revokeAdmin := seedEnrollmentKeyRole(ctx, t, admin, confirmer, 1991, "admin")
	owner := confirmer
	issued, err := service.Issue(ctx, owner, enrollmentkey.IssueRequest{
		Scope: members.scope, Description: "build server",
		DeviceLifetime: enrollment.NeverExpiringDeviceLifetime(), CorrelationID: newCorrelationID(t),
	})
	if err != nil {
		t.Fatalf("admin issue key: %v", err)
	}
	key := issued.Key()
	if !issued.Presentation().IsValid() || issued.Presentation().CredentialID() != key.ID() ||
		key.State() != enrollmentkey.StateActive || key.Description() != "build server" ||
		key.IssuedBy() != owner.PrincipalID() ||
		key.DeviceLifetime() != enrollment.NeverExpiringDeviceLifetime() {
		t.Fatalf("issued key = %+v", key)
	}
	var validity time.Duration
	var maxUses int64
	var storedDigest []byte
	if err := admin.QueryRow(ctx, `SELECT expires_at - valid_from, max_uses, token_digest
FROM mesh.enrollment_credential WHERE public_id = $1::UUID AND device_never_expires`,
		key.ID().String()).Scan(&validity, &maxUses, &storedDigest); err != nil {
		t.Fatalf("read issued key: %v", err)
	}
	if validity != 24*time.Hour || maxUses != 1 || len(storedDigest) != 32 {
		t.Fatalf("issued key validity %v, uses %d, digest %d bytes; want 24h, 1, 32", validity, maxUses, len(storedDigest))
	}
	assertEnrollmentKeyEvent(ctx, t, admin, key.ID().String(), "enrollment_key.created",
		map[string]any{"device_lifetime": "never", "description": "build server"})

	listed, err := service.List(ctx, owner, members.scope)
	if err != nil || len(listed) == 0 {
		t.Fatalf("list keys = %d, %v", len(listed), err)
	}
	encoded, _ := json.Marshal(listed)
	if bytes.Contains(encoded, []byte(issued.Presentation().Reveal())) {
		t.Fatal("listing a key revealed its secret")
	}

	fixed, err := enrollment.NewDeviceLifetime(72 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]enrollmentkey.IssueRequest{
		"a key valid for over 30 days": {Scope: members.scope, DeviceLifetime: fixed,
			KeyLifetime: 31 * 24 * time.Hour, CorrelationID: newCorrelationID(t)},
		"a key valid for under 5 minutes": {Scope: members.scope, DeviceLifetime: fixed,
			KeyLifetime: time.Minute, CorrelationID: newCorrelationID(t)},
		"no Device lifetime": {Scope: members.scope, CorrelationID: newCorrelationID(t)},
	} {
		if _, err := service.Issue(ctx, owner, request); !errors.Is(err, enrollmentkey.ErrInvalid) {
			t.Fatalf("issue %s: %v", name, err)
		}
	}
	if _, err := service.Revoke(ctx, owner, members.scope, key.ID(), newCorrelationID(t)); err != nil {
		t.Fatalf("clean up the never-expiring key: %v", err)
	}
	assertEnrollmentKeyUse(ctx, t, admin, runtimePool, service, owner, members.scope)
	revokeAdmin()

	revokeNetworkAdmin := seedEnrollmentKeyRole(ctx, t, admin, confirmer, 1992, "network_admin")
	if _, err := service.Issue(ctx, confirmer, enrollmentkey.IssueRequest{
		Scope: members.scope, DeviceLifetime: fixed, KeyLifetime: time.Hour, CorrelationID: newCorrelationID(t),
	}); !errors.Is(err, enrollmentkey.ErrForbidden) {
		t.Fatalf("network_admin issued a key: %v", err)
	}
	if _, err := service.Revoke(ctx, confirmer, members.scope, key.ID(), newCorrelationID(t)); !errors.Is(err,
		enrollmentkey.ErrForbidden) {
		t.Fatalf("network_admin revoked a key: %v", err)
	}
	revokeNetworkAdmin()

	revokeITAdmin := seedEnrollmentKeyRole(ctx, t, admin, confirmer, 1993, "it_admin")
	short, err := service.Issue(ctx, confirmer, enrollmentkey.IssueRequest{
		Scope: members.scope, DeviceLifetime: fixed, KeyLifetime: time.Hour, CorrelationID: newCorrelationID(t),
	})
	if err != nil || short.Key().IssuedBy() != confirmer.PrincipalID() || short.Key().DeviceLifetime() != fixed {
		t.Fatalf("it_admin issue = %+v, %v", short.Key(), err)
	}
	revoked, err := service.Revoke(ctx, confirmer, members.scope, short.Key().ID(), newCorrelationID(t))
	if err != nil || revoked.State() != enrollmentkey.StateRevoked {
		t.Fatalf("it_admin revoke = %+v, %v", revoked, err)
	}
	if _, err := service.Revoke(ctx, confirmer, members.scope, short.Key().ID(), newCorrelationID(t)); !errors.Is(err,
		enrollmentkey.ErrNotActive) {
		t.Fatalf("revoking a revoked key again: %v", err)
	}
	revokeITAdmin()
	assertEnrollmentKeyEvent(ctx, t, admin, short.Key().ID().String(), "enrollment_key.created",
		map[string]any{"device_lifetime_seconds": float64(72 * 3600), "key_lifetime_seconds": float64(3600)})
	assertEnrollmentKeyEvent(ctx, t, admin, short.Key().ID().String(), "enrollment_key.revoked", nil)
}

// assertEnrollmentKeyEvent checks one event on the key's Network stream and
// the given payload fields.
func assertEnrollmentKeyEvent(ctx context.Context, t *testing.T, admin *pgx.Conn, keyID, action string,
	want map[string]any) {
	t.Helper()
	var encoded []byte
	if err := admin.QueryRow(ctx, `SELECT payload::TEXT FROM mesh_audit.audit_event
WHERE target_kind = 'enrollment_credential' AND target_public_id = $1::UUID AND action = $2`,
		keyID, action).Scan(&encoded); err != nil {
		t.Fatalf("read %s event of key %s: %v", action, keyID, err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	for field, value := range want {
		if payload[field] != value {
			t.Fatalf("%s payload %s = %v, want %v (payload %s)", action, field, payload[field], value, encoded)
		}
	}
}

// seedEnrollmentKeyRole gives the session's principal a Workspace-scope
// built-in role directly (fixture statements, triggers bypassed), so the
// checks do not depend on which roles earlier checks left behind, and
// returns its removal.
func seedEnrollmentKeyRole(ctx context.Context, t *testing.T, admin *pgx.Conn, session accountsession.Session,
	id int64, role string) func() {
	t.Helper()
	principal := publicid.ID(session.PrincipalID()).String()
	runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{sql: `INSERT INTO mesh.workspace_role_assignment (
    id, public_id, deployment_id, workspace_id, principal_id, workspace_membership_id, role_key, state,
    authority_generation, valid_from, version, created_at, updated_at)
OVERRIDING SYSTEM VALUE SELECT $1, pg_catalog.uuidv7(), membership.deployment_id, 103, principal.id, membership.id,
    $3, 'active', 1, now() - INTERVAL '1 minute', 1, now() - INTERVAL '1 minute', now() - INTERVAL '1 minute'
FROM mesh.principal AS principal
JOIN mesh.workspace_membership AS membership ON membership.workspace_id = 103 AND membership.principal_id = principal.id
WHERE principal.public_id = $2::UUID`, args: []any{id, principal, role}}})
	return func() {
		runRemovalFixture(ctx, t, admin, []removalFixtureStatement{{
			sql: `DELETE FROM mesh.workspace_role_assignment WHERE id = $1`, args: []any{id}}})
	}
}

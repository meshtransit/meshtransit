//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/identity/accountsession"
)

type keyDocumentFixture struct {
	ID          string     `json:"id"`
	SessionID   string     `json:"session_id"`
	WorkspaceID string     `json:"workspace_id"`
	PrincipalID string     `json:"principal_id"`
	Name        string     `json:"name"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	ExpiresAt   time.Time  `json:"expires_at"`
	EndedAt     *time.Time `json:"ended_at"`
	EndReason   *string    `json:"end_reason"`
	State       string     `json:"state"`
}

type keyListPageFixture struct {
	WorkspaceID string               `json:"workspace_id"`
	PrincipalID string               `json:"principal_id"`
	Keys        []keyDocumentFixture `json:"keys"`
	HasMore     bool                 `json:"has_more"`
}

type keyRevokeResultFixture struct {
	Key            keyDocumentFixture `json:"key"`
	SessionID      string             `json:"session_id"`
	SessionVersion int64              `json:"session_version"`
	RevokedBy      string             `json:"revoked_by"`
	Authority      map[string]any     `json:"authority"`
}

// assertPostgreSQLAPIKeyLifecycle drives schema 322 (V1-80 A2, part 2):
// mesh.api_key and mesh.api_key_usage plus create, resolve, touch, list,
// read, and revoke across owner, self-key, and manager paths.
func assertPostgreSQLAPIKeyLifecycle(ctx context.Context, t *testing.T, admin *pgx.Conn, owner accountsession.Session) {
	t.Helper()
	f := loadLifecycleFixture(ctx, t, admin, owner.ID().String())
	assertKeyCreateAndImmutability(ctx, t, admin, owner.ID().String(), f)
	assertKeyCreateRefusals(ctx, t, admin, owner.ID().String(), f)
	assertKeyQuotaLimits(ctx, t, admin, owner.ID().String(), f)
	assertKeyResolveAndTouch(ctx, t, admin, owner.ID().String(), f)
	assertKeyResolveLiveFences(ctx, t, admin, owner.ID().String(), f)
	assertKeyListReadAndRevoke(ctx, t, admin, owner.ID().String(), f)
	assertKeyDelegationCeilingAndExpiry(ctx, t, admin, owner.ID().String(), f)
}

func loadLifecycleFixture(ctx context.Context, t *testing.T, admin *pgx.Conn, ownerSession string) apiKeyMemberFixture {
	t.Helper()
	f := apiKeyMemberFixture{
		manager:         "01890f00-0000-7000-8000-00000000a9d0",
		memberPrincipal: "01890f00-0000-7000-8000-00000000a9d1",
		human:           "01890f00-0000-7000-8000-00000000a9d4",
		keyHere:         "01890f00-0000-7000-8000-00000000a9d5",
		keyOut:          "01890f00-0000-7000-8000-00000000a9d6",
	}
	if err := admin.QueryRow(ctx, `SELECT workspace.public_id::TEXT FROM mesh.account_session AS session
JOIN mesh.workspace AS workspace ON workspace.owner_principal_id = session.principal_id AND workspace.state = 'active'
JOIN mesh.network AS network ON network.workspace_id = workspace.id AND network.state = 'active'
JOIN mesh.workspace_membership AS membership ON membership.workspace_id = workspace.id
 AND membership.principal_id = session.principal_id AND membership.state = 'active'
WHERE session.public_id = $1::UUID ORDER BY 1 LIMIT 1`, ownerSession).Scan(&f.workspace); err != nil {
		t.Fatalf("lifecycle workspace: %v", err)
	}
	if err := admin.QueryRow(ctx, `SELECT workspace.public_id::TEXT FROM mesh.account_session AS session
JOIN mesh.workspace AS workspace ON workspace.deployment_id = session.deployment_id AND workspace.state = 'active'
WHERE session.public_id = $1::UUID AND workspace.public_id <> $2::UUID ORDER BY 1 LIMIT 1`,
		ownerSession, f.workspace).Scan(&f.elsewhere); err != nil {
		t.Fatalf("lifecycle second workspace: %v", err)
	}
	return f
}

func assertKeyCreateAndImmutability(ctx context.Context, t *testing.T, admin *pgx.Conn,
	ownerSession string, f apiKeyMemberFixture,
) {
	t.Helper()
	tx := beginSeededAPIKeyMemberTx(ctx, t, admin, ownerSession, f, "create")
	defer func() { _ = tx.Rollback(ctx) }()
	keyID := "01890f00-0000-7000-8000-00000000b101"
	keySessID := "01890f00-0000-7000-8000-00000000b102"
	raw := mustCreateKeyTx(ctx, t, tx, f.human, f.workspace, keyID, keySessID, "ci-deploy", 30*24*time.Hour, "b101")
	doc := decodeCreatedKey(t, raw)
	if doc.ID != keyID || doc.SessionID != keySessID || doc.WorkspaceID != f.workspace ||
		doc.PrincipalID != f.memberPrincipal || doc.State != "active" || doc.LastUsedAt != nil {
		t.Fatalf("unexpected created key doc: %+v", doc)
	}
	var kind, state string
	if err := tx.QueryRow(ctx, `SELECT kind, state FROM mesh.account_session WHERE public_id = $1::UUID`,
		keySessID).Scan(&kind, &state); err != nil || kind != "api_key" || state != "api_key" {
		t.Fatalf("created key session row = (%q, %q, %v), want ('api_key', 'api_key')", kind, state, err)
	}
	if got := txWorkspaceKeyResolves(ctx, t, tx, keySessID, f.workspace); got != 1 {
		t.Errorf("created key did not resolve member.read in own Workspace: %d", got)
	}
	if got := txWorkspaceKeyResolves(ctx, t, tx, keySessID, f.elsewhere); got != 0 {
		t.Errorf("created key resolved member.read in another Workspace: %d", got)
	}
	assertTxRefused(ctx, t, tx, "update api_key", "55000", "API key metadata cannot be modified",
		`UPDATE mesh.api_key SET name = 'other' WHERE public_id = $1::UUID`, keyID)
	assertTxRefused(ctx, t, tx, "delete api_key", "55000", "API key metadata cannot be modified",
		`DELETE FROM mesh.api_key WHERE public_id = $1::UUID`, keyID)
}

func assertKeyCreateRefusals(ctx context.Context, t *testing.T, admin *pgx.Conn,
	ownerSession string, f apiKeyMemberFixture,
) {
	t.Helper()
	cases := []struct {
		name, actor, ws, keyName, code, msg string
		ttl                                 time.Duration
		setup                               string
	}{
		{"api key caller", f.keyHere, f.workspace, "from-key", "42501", "API key creation is not authorized", 30 * 24 * time.Hour, ""},
		{"other workspace", f.human, f.elsewhere, "wrong-ws", "42501", "API key creation is not authorized", 30 * 24 * time.Hour, ""},
		{"stale auth", f.human, f.workspace, "stale", "MTA20", "API key creation requires recent authentication", 30 * 24 * time.Hour,
			`UPDATE mesh.account_session SET authentication_time = pg_catalog.transaction_timestamp() - interval '16 minutes' WHERE public_id = $1::UUID`},
		{"too short", f.human, f.workspace, "short", "22023", "invalid API key creation input", 6 * 24 * time.Hour, ""},
		{"too long", f.human, f.workspace, "long", "22023", "invalid API key creation input", 366 * 24 * time.Hour, ""},
		{"control char", f.human, f.workspace, "bad\nname", "22023", "invalid API key creation input", 30 * 24 * time.Hour, ""},
		{"untrimmed", f.human, f.workspace, " padded ", "22023", "invalid API key creation input", 30 * 24 * time.Hour, ""},
	}
	for i, tc := range cases {
		tx := beginSeededAPIKeyMemberTx(ctx, t, admin, ownerSession, f, tc.name)
		if tc.setup != "" {
			execReplicaTx(ctx, t, tx, tc.setup, f.human)
		}
		_, err := callCreateKeyTx(ctx, tx, tc.actor, tc.ws,
			fmt.Sprintf("01890f00-0000-7000-8000-00000000b2%02x", i+1),
			fmt.Sprintf("01890f00-0000-7000-8000-00000000b3%02x", i+1),
			tc.keyName, tc.ttl, fmt.Sprintf("b2%02x", i+1))
		assertPGError(t, tc.name, err, tc.code, tc.msg)
		_ = tx.Rollback(ctx)
	}
}

func assertKeyQuotaLimits(ctx context.Context, t *testing.T, admin *pgx.Conn,
	ownerSession string, f apiKeyMemberFixture,
) {
	t.Helper()
	tx := beginSeededAPIKeyMemberTx(ctx, t, admin, ownerSession, f, "principal quota")
	defer func() { _ = tx.Rollback(ctx) }()
	// Fixture already has 1 live key (f.keyHere) for member in f.workspace.
	seedLiveKeySessionsTx(ctx, t, tx, f.keyHere, 18)
	key20 := "01890f00-0000-7000-8000-00000000b420"
	sess20 := "01890f00-0000-7000-8000-00000000b520"
	_ = mustCreateKeyTx(ctx, t, tx, f.human, f.workspace, key20, sess20, "key-20", 30*24*time.Hour, "b420")
	err := inSavepointTx(ctx, t, tx, func() error {
		_, callErr := callCreateKeyTx(ctx, tx, f.human, f.workspace,
			"01890f00-0000-7000-8000-00000000b421", "01890f00-0000-7000-8000-00000000b521",
			"key-21", 30*24*time.Hour, "b421")
		return callErr
	})
	assertPGError(t, "21st principal key", err, "MTA21", "principal API key limit reached")
	_ = mustRevokeKeyTx(ctx, t, tx, f.human, f.workspace, "", key20)
	_ = mustCreateKeyTx(ctx, t, tx, f.human, f.workspace,
		"01890f00-0000-7000-8000-00000000b422", "01890f00-0000-7000-8000-00000000b522",
		"key-after-revoke", 30*24*time.Hour, "b422")
	_ = tx.Rollback(ctx)

	txWS := beginSeededAPIKeyMemberTx(ctx, t, admin, ownerSession, f, "workspace quota")
	defer func() { _ = txWS.Rollback(ctx) }()
	// Seed 498 live keys for owner + 1 existing member key = 499; 500th succeeds, 501st fails.
	seedLiveKeySessionsTx(ctx, t, txWS, f.manager, 498)
	_ = mustCreateKeyTx(ctx, t, txWS, f.human, f.workspace,
		"01890f00-0000-7000-8000-00000000b498", "01890f00-0000-7000-8000-00000000b598",
		"ws-500th", 30*24*time.Hour, "b498")
	_, err = callCreateKeyTx(ctx, txWS, f.human, f.workspace,
		"01890f00-0000-7000-8000-00000000b499", "01890f00-0000-7000-8000-00000000b599",
		"ws-over-500", 30*24*time.Hour, "b499")
	assertPGError(t, "501st workspace key", err, "MTA21", "Workspace API key limit reached")
}

func assertKeyResolveAndTouch(ctx context.Context, t *testing.T, admin *pgx.Conn,
	ownerSession string, f apiKeyMemberFixture,
) {
	t.Helper()
	tx := beginSeededAPIKeyMemberTx(ctx, t, admin, ownerSession, f, "resolve and touch")
	defer func() { _ = tx.Rollback(ctx) }()
	keyID := "01890f00-0000-7000-8000-00000000b601"
	keySessID := "01890f00-0000-7000-8000-00000000b602"
	_ = mustCreateKeyTx(ctx, t, tx, f.human, f.workspace, keyID, keySessID, "touch-test", 30*24*time.Hour, "b601")

	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.workspace_id', '', TRUE)`); err != nil {
		t.Fatal(err)
	}
	count, alg, keyKid, lastUsed := resolveKeyRowTx(ctx, t, tx, f.human, keyID)
	if count != 1 || alg != "hmac-sha256-v1" || keyKid != "api-key-v1" || lastUsed != nil {
		t.Fatalf("baseline resolve = (count=%d, alg=%q, kid=%q, lastUsed=%v)", count, alg, keyKid, lastUsed)
	}
	var restoredScope string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(pg_catalog.current_setting('mesh.workspace_id', TRUE), '')`).Scan(&restoredScope); err != nil || restoredScope != "" {
		t.Errorf("resolve_api_key_v1 leaked mesh.workspace_id = %q (err=%v)", restoredScope, err)
	}
	if !touchKeyUsageTx(ctx, t, tx, f.human, keyID) {
		t.Fatal("first touch_api_key_usage_v1 returned false, want true")
	}
	_, _, _, lastUsed = resolveKeyRowTx(ctx, t, tx, f.human, keyID)
	if lastUsed == nil {
		t.Fatal("last_used_at remained nil after first touch")
	}
	if touchKeyUsageTx(ctx, t, tx, f.human, keyID) {
		t.Error("immediate repeat touch within 5 minutes returned true, want false")
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh.api_key_usage SET last_used_at = last_used_at - interval '6 minutes'
WHERE api_key_id = (SELECT id FROM mesh.api_key WHERE public_id = $1::UUID)`, keyID); err != nil {
		t.Fatal(err)
	}
	if !touchKeyUsageTx(ctx, t, tx, f.human, keyID) {
		t.Error("touch after 6 minutes returned false, want true")
	}
}

func assertKeyResolveLiveFences(ctx context.Context, t *testing.T, admin *pgx.Conn,
	ownerSession string, f apiKeyMemberFixture,
) {
	t.Helper()
	for i, tc := range keyResolveFenceCases() {
		tx := beginSeededAPIKeyMemberTx(ctx, t, admin, ownerSession, f, tc.name)
		keyID := fmt.Sprintf("01890f00-0000-7000-8000-00000000b7%02x", i+1)
		sessID := fmt.Sprintf("01890f00-0000-7000-8000-00000000b8%02x", i+1)
		_ = mustCreateKeyTx(ctx, t, tx, f.human, f.workspace, keyID, sessID, tc.name, 30*24*time.Hour, fmt.Sprintf("b7%02x", i+1))
		if n, _, _, _ := resolveKeyRowTx(ctx, t, tx, f.human, keyID); n != 1 {
			_ = tx.Rollback(ctx)
			t.Fatalf("baseline %s: resolve count = %d, want 1", tc.name, n)
		}
		execReplicaTx(ctx, t, tx, tc.mutate, keyID, sessID, f.workspace)
		if n, _, _, _ := resolveKeyRowTx(ctx, t, tx, f.human, keyID); n != 0 {
			t.Errorf("fence %s: resolve_api_key_v1 admitted key (%d rows)", tc.name, n)
		}
		if (tc.name == "revoked" || tc.name == "expired") && touchKeyUsageTx(ctx, t, tx, f.human, keyID) {
			t.Errorf("fence %s: touch_api_key_usage_v1 returned true", tc.name)
		}
		_ = tx.Rollback(ctx)
	}
}

func keyResolveFenceCases() []struct{ name, mutate string } {
	return []struct{ name, mutate string }{
		{"revoked", `UPDATE mesh.account_session SET state = 'revoked', ended_at = pg_catalog.transaction_timestamp(),
    end_reason = 'api_key_revoked', version = version + 1 WHERE public_id = $2::UUID AND $1::UUID IS NOT NULL AND $3::UUID IS NOT NULL`},
		{"expired", `UPDATE mesh.account_session SET idle_expires_at = issued_at - interval '30 minutes',
    absolute_expires_at = issued_at - interval '30 minutes', issued_at = issued_at - interval '1 hour',
    last_used_at = last_used_at - interval '1 hour', authentication_time = authentication_time - interval '1 hour',
    created_at = created_at - interval '1 hour' WHERE public_id = $2::UUID AND $1::UUID IS NOT NULL AND $3::UUID IS NOT NULL`},
		{"suspended membership", `UPDATE mesh.workspace_membership SET state = 'suspended'
WHERE principal_id = 970321 AND $1::UUID IS NOT NULL AND $2::UUID IS NOT NULL AND $3::UUID IS NOT NULL`},
		{"bumped session generation", `UPDATE mesh.account SET session_generation = session_generation + 1
WHERE principal_id = 970321 AND $1::UUID IS NOT NULL AND $2::UUID IS NOT NULL AND $3::UUID IS NOT NULL`},
		{"quarantined account", `UPDATE mesh.account SET recovery_state = 'quarantined'
WHERE principal_id = 970321 AND $1::UUID IS NOT NULL AND $2::UUID IS NOT NULL AND $3::UUID IS NOT NULL`},
		{"suspended IdP route", `UPDATE mesh.workspace_identity_provider SET state = 'suspended'
WHERE workspace_id = (SELECT id FROM mesh.workspace WHERE public_id = $3::UUID) AND $1::UUID IS NOT NULL AND $2::UUID IS NOT NULL`},
	}
}

func assertKeyListReadAndRevoke(ctx context.Context, t *testing.T, admin *pgx.Conn,
	ownerSession string, f apiKeyMemberFixture,
) {
	t.Helper()
	tx := beginSeededAPIKeyMemberTx(ctx, t, admin, ownerSession, f, "list read revoke")
	defer func() { _ = tx.Rollback(ctx) }()
	empty := mustListKeysTx(ctx, t, tx, f.human, f.workspace, "", nil, "", 10)
	if len(empty.Keys) != 0 || empty.HasMore {
		t.Fatalf("empty list = (%d, %v), want (0, false)", len(empty.Keys), empty.HasMore)
	}
	keyIDs, sessIDs := createNumberedKeysTx(ctx, t, tx, f, 12)
	assertKeyPaginationAndReadTx(ctx, t, tx, f, keyIDs, sessIDs)
	assertKeyThreeRevokePathsTx(ctx, t, tx, f, keyIDs, sessIDs)
}

func createNumberedKeysTx(ctx context.Context, t *testing.T, tx pgx.Tx, f apiKeyMemberFixture, n int) ([]string, []string) {
	t.Helper()
	keyIDs := make([]string, n)
	sessIDs := make([]string, n)
	for i := range n {
		keyIDs[i] = fmt.Sprintf("01890f00-0000-7000-8000-00000000c1%02x", i+1)
		sessIDs[i] = fmt.Sprintf("01890f00-0000-7000-8000-00000000c2%02x", i+1)
		_ = mustCreateKeyTx(ctx, t, tx, f.human, f.workspace, keyIDs[i], sessIDs[i],
			fmt.Sprintf("key-%02d", i+1), 30*24*time.Hour, fmt.Sprintf("c1%02x", i+1))
	}
	return keyIDs, sessIDs
}

func assertKeyPaginationAndReadTx(ctx context.Context, t *testing.T, tx pgx.Tx,
	f apiKeyMemberFixture, keyIDs, sessIDs []string,
) {
	t.Helper()
	page1 := mustListKeysTx(ctx, t, tx, f.human, f.workspace, "", nil, "", 10)
	if len(page1.Keys) != 10 || !page1.HasMore {
		t.Fatalf("page1 = (%d keys, has_more=%v), want (10, true)", len(page1.Keys), page1.HasMore)
	}
	last := page1.Keys[len(page1.Keys)-1]
	page2 := mustListKeysTx(ctx, t, tx, f.human, f.workspace, "", &last.CreatedAt, last.ID, 10)
	if len(page2.Keys) != 2 || page2.HasMore {
		t.Fatalf("page2 = (%d keys, has_more=%v), want (2, false)", len(page2.Keys), page2.HasMore)
	}
	seen := map[string]struct{}{}
	for _, k := range append(page1.Keys, page2.Keys...) {
		seen[k.ID] = struct{}{}
	}
	if len(seen) != 12 {
		t.Errorf("paginated key count = %d distinct, want 12", len(seen))
	}
	if readDoc := mustReadKeyTx(ctx, t, tx, f.human, f.workspace, keyIDs[0]); readDoc.ID != keyIDs[0] {
		t.Errorf("read_api_key_v1 returned %q, want %q", readDoc.ID, keyIDs[0])
	}
	err := inSavepointTx(ctx, t, tx, func() error {
		_, callErr := callListKeysTx(ctx, tx, sessIDs[0], f.workspace, "", nil, "", 10)
		return callErr
	})
	assertPGError(t, "api key list refused", err, "42501", "API key listing is not authorized")
	err = inSavepointTx(ctx, t, tx, func() error {
		_, callErr := callReadKeyTx(ctx, tx, sessIDs[0], f.workspace, keyIDs[0])
		return callErr
	})
	assertPGError(t, "api key read refused", err, "42501", "API key read is not authorized")
}

func assertKeyThreeRevokePathsTx(ctx context.Context, t *testing.T, tx pgx.Tx,
	f apiKeyMemberFixture, keyIDs, sessIDs []string,
) {
	t.Helper()
	rev1 := mustRevokeKeyTx(ctx, t, tx, f.human, f.workspace, "", keyIDs[0])
	if rev1.RevokedBy != "owner" || rev1.Key.State != "revoked" || rev1.Key.EndReason == nil || *rev1.Key.EndReason != "api_key_revoked" {
		t.Fatalf("owner revoke = %+v", rev1)
	}
	err := inSavepointTx(ctx, t, tx, func() error {
		_, callErr := callRevokeKeyTx(ctx, tx, f.human, f.workspace, "", keyIDs[0])
		return callErr
	})
	assertPGError(t, "repeat revoke", err, "MTA22", "API key is already ended")
	err = inSavepointTx(ctx, t, tx, func() error {
		_, callErr := callRevokeKeyTx(ctx, tx, sessIDs[1], f.workspace, "", keyIDs[2])
		return callErr
	})
	assertPGError(t, "key revoke sibling", err, "42501", "API key may only revoke itself")
	err = inSavepointTx(ctx, t, tx, func() error {
		_, callErr := callRevokeKeyTx(ctx, tx, sessIDs[1], f.workspace, "", "01890f00-0000-7000-8000-00000000c999")
		return callErr
	})
	assertPGError(t, "key revoke unknown", err, "42501", "API key may only revoke itself")
	rev2 := mustRevokeKeyTx(ctx, t, tx, sessIDs[1], f.workspace, "", keyIDs[1])
	if rev2.RevokedBy != "self_key" || rev2.Key.State != "revoked" {
		t.Fatalf("self revoke = %+v", rev2)
	}
	if n, _, _, _ := resolveKeyRowTx(ctx, t, tx, f.human, keyIDs[1]); n != 0 {
		t.Errorf("self-revoked key still resolved (%d rows)", n)
	}
	mgrPage := mustListKeysTx(ctx, t, tx, f.manager, f.workspace, f.memberPrincipal, nil, "", 10)
	if len(mgrPage.Keys) != 10 || !mgrPage.HasMore {
		t.Fatalf("manager list = (%d, %v), want (10, true)", len(mgrPage.Keys), mgrPage.HasMore)
	}
	err = inSavepointTx(ctx, t, tx, func() error {
		_, callErr := callRevokeKeyTx(ctx, tx, sessIDs[2], f.workspace, f.memberPrincipal, keyIDs[2])
		return callErr
	})
	assertPGError(t, "api key manager revoke", err, "42501", "API key revocation is not authorized")
	rev3 := mustRevokeKeyTx(ctx, t, tx, f.manager, f.workspace, f.memberPrincipal, keyIDs[2])
	if rev3.RevokedBy != "manager" || rev3.Key.State != "revoked" || len(rev3.Authority) == 0 {
		t.Fatalf("manager revoke = %+v", rev3)
	}
}

func assertKeyDelegationCeilingAndExpiry(ctx context.Context, t *testing.T, admin *pgx.Conn,
	ownerSession string, f apiKeyMemberFixture,
) {
	t.Helper()
	tx := beginSeededAPIKeyMemberTx(ctx, t, admin, ownerSession, f, "ceiling and expiry")
	defer func() { _ = tx.Rollback(ctx) }()
	keyID := "01890f00-0000-7000-8000-00000000c301"
	sessID := "01890f00-0000-7000-8000-00000000c302"
	_ = mustCreateKeyTx(ctx, t, tx, f.human, f.workspace, keyID, sessID, "expiring", 30*24*time.Hour, "c301")
	assertOwnerAndCeilingRefusalsTx(ctx, t, tx, ownerSession, f, keyID)
	execReplicaTx(ctx, t, tx, `UPDATE mesh.account_session SET idle_expires_at = issued_at - interval '30 minutes',
    absolute_expires_at = issued_at - interval '30 minutes', issued_at = issued_at - interval '1 hour',
    last_used_at = last_used_at - interval '1 hour', authentication_time = authentication_time - interval '1 hour',
    created_at = created_at - interval '1 hour' WHERE public_id = $1::UUID`, sessID)
	err := inSavepointTx(ctx, t, tx, func() error {
		_, callErr := callRevokeKeyTx(ctx, tx, f.human, f.workspace, "", keyID)
		return callErr
	})
	assertPGError(t, "revoke expired key", err, "MTA22", "API key has expired")
}

func assertOwnerAndCeilingRefusalsTx(ctx context.Context, t *testing.T, tx pgx.Tx,
	ownerSession string, f apiKeyMemberFixture, keyID string,
) {
	t.Helper()
	var ownerPrincipal string
	if err := tx.QueryRow(ctx, `SELECT p.public_id::TEXT FROM mesh.account_session AS s
JOIN mesh.principal AS p ON p.id = s.principal_id WHERE s.public_id = $1::UUID`, f.manager).Scan(&ownerPrincipal); err != nil {
		t.Fatal(err)
	}
	err := inSavepointTx(ctx, t, tx, func() error {
		_, callErr := callListKeysTx(ctx, tx, f.manager, f.workspace, ownerPrincipal, nil, "", 10)
		return callErr
	})
	assertPGError(t, "manager list owner", err, "MTM02", "nobody manages the API keys of the owner or themselves")
	err = inSavepointTx(ctx, t, tx, func() error {
		_, callErr := callRevokeKeyTx(ctx, tx, f.manager, f.workspace, ownerPrincipal, keyID)
		return callErr
	})
	assertPGError(t, "manager revoke owner", err, "MTM02", "nobody manages the API keys of the owner or themselves")
	itAdminSess := seedITAdminAndPromoteMemberTx(ctx, t, tx, ownerSession, f.workspace)
	err = inSavepointTx(ctx, t, tx, func() error {
		_, callErr := callListKeysTx(ctx, tx, itAdminSess, f.workspace, f.memberPrincipal, nil, "", 10)
		return callErr
	})
	assertPGError(t, "ceiling list", err, "42501", "the member holds a role beyond the delegation ceiling")
	err = inSavepointTx(ctx, t, tx, func() error {
		_, callErr := callRevokeKeyTx(ctx, tx, itAdminSess, f.workspace, f.memberPrincipal, keyID)
		return callErr
	})
	assertPGError(t, "ceiling revoke", err, "42501", "the member holds a role beyond the delegation ceiling")
}

func seedITAdminAndPromoteMemberTx(ctx context.Context, t *testing.T, tx pgx.Tx, ownerSession, ws string) string {
	t.Helper()
	sessID := "01890f00-0000-7000-8000-00000000c399"
	stmts := []struct {
		sql  string
		args []any
	}{
		{`SET LOCAL session_replication_role = replica`, nil},
		{`UPDATE mesh.workspace_role_assignment SET role_key = 'admin' WHERE id = 970321`, nil},
		{`INSERT INTO mesh.principal (id, public_id, deployment_id, kind, state) OVERRIDING SYSTEM VALUE
SELECT 970325, '01890f00-0000-7000-8000-00000000c395'::UUID, s.deployment_id, 'account', 'active'
FROM mesh.account_session AS s WHERE s.public_id = $1::UUID`, []any{ownerSession}},
		{`INSERT INTO mesh.account (id, public_id, deployment_id, principal_id, display_name, session_generation, recovery_state)
OVERRIDING SYSTEM VALUE SELECT 970325, '01890f00-0000-7000-8000-00000000c396'::UUID, s.deployment_id, 970325,
    'IT Admin', 1, 'verified' FROM mesh.account_session AS s WHERE s.public_id = $1::UUID`, []any{ownerSession}},
		{`INSERT INTO mesh.identity_subject (id, public_id, deployment_id, identity_provider_id, principal_id,
    subject_digest_algorithm, subject_digest_key_id, subject_digest, claims_revision, last_seen_at, state)
OVERRIDING SYSTEM VALUE SELECT 970325, '01890f00-0000-7000-8000-00000000c397'::UUID, s.deployment_id,
    s.identity_provider_id, 970325, 'hmac-sha256-v1', 'integration-v1', pg_catalog.sha256('c397'::BYTEA), 1,
    pg_catalog.transaction_timestamp(), 'active' FROM mesh.account_session AS s WHERE s.public_id = $1::UUID`, []any{ownerSession}},
		{`INSERT INTO mesh.workspace_membership (id, public_id, deployment_id, workspace_id, principal_id,
    state, authority_generation, valid_from) OVERRIDING SYSTEM VALUE
SELECT 970325, pg_catalog.uuidv7(), ws.deployment_id, ws.id, 970325, 'active', 1,
    pg_catalog.transaction_timestamp() - interval '1 minute' FROM mesh.workspace AS ws WHERE ws.public_id = $1::UUID`, []any{ws}},
		{`INSERT INTO mesh.workspace_role_assignment (id, public_id, deployment_id, workspace_id, principal_id,
    workspace_membership_id, role_key, state, authority_generation, valid_from, created_at, updated_at)
OVERRIDING SYSTEM VALUE SELECT 970325, pg_catalog.uuidv7(), ws.deployment_id, ws.id, 970325, 970325,
    'it_admin', 'active', 1, now.at - interval '1 minute', now.at - interval '1 minute', now.at - interval '1 minute'
FROM mesh.workspace AS ws CROSS JOIN (SELECT pg_catalog.transaction_timestamp() AS at) AS now WHERE ws.public_id = $1::UUID`, []any{ws}},
		{`INSERT INTO mesh.account_session (` + sessionRowColumns + `)
SELECT $3::UUID, s.deployment_id, 970325, s.identity_provider_id, 970325, s.identity_provider_client_id, ws.id,
    s.token_digest_algorithm, s.token_digest_key_id, pg_catalog.sha256('c399'::BYTEA), p.current_generation,
    now.at - interval '1 minute', s.acr, s.amr, 1, 1, d.recovery_epoch, now.at - interval '1 minute',
    now.at - interval '1 minute', now.at + interval '1 hour', now.at + interval '1 hour',
    'active', 'interactive', now.at - interval '1 minute', now.at - interval '1 minute'
FROM mesh.account_session AS s JOIN mesh.deployment AS d ON d.id = s.deployment_id
JOIN mesh.identity_provider AS p ON p.id = s.identity_provider_id JOIN mesh.workspace AS ws ON ws.public_id = $2::UUID
CROSS JOIN (SELECT pg_catalog.transaction_timestamp() AS at) AS now WHERE s.public_id = $1::UUID`, []any{ownerSession, ws, sessID}},
		{`SET LOCAL session_replication_role = origin`, nil},
	}
	for _, stmt := range stmts {
		if _, err := tx.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("seed it_admin: %v", err)
		}
	}
	return sessID
}

func seedLiveKeySessionsTx(ctx context.Context, t *testing.T, tx pgx.Tx, templateSession string, count int) {
	t.Helper()
	execReplicaTx(ctx, t, tx, `INSERT INTO mesh.account_session (`+sessionRowColumns+`)
SELECT pg_catalog.uuidv7(), s.deployment_id, s.principal_id, s.identity_provider_id, s.identity_subject_id,
    s.identity_provider_client_id, s.login_workspace_id, 'hmac-sha256-v1', 'api-key-v1',
    pg_catalog.sha256(pg_catalog.convert_to($1::TEXT || ':' || gs::TEXT, 'UTF8')), s.provider_generation,
    now.at - interval '1 minute', s.acr, s.amr, s.principal_authority_generation, s.account_session_generation,
    s.deployment_recovery_epoch, now.at, now.at, now.at + interval '30 days', now.at + interval '30 days',
    'api_key', 'api_key', now.at, now.at
FROM mesh.account_session AS s
CROSS JOIN pg_catalog.generate_series(1, $2) AS gs
CROSS JOIN (SELECT pg_catalog.transaction_timestamp() AS at) AS now
WHERE s.public_id = $1::UUID`, templateSession, count)
}

func execReplicaTx(ctx context.Context, t *testing.T, tx pgx.Tx, stmt string, args ...any) {
	t.Helper()
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, stmt, args...); err != nil {
		t.Fatalf("replica exec: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
}

func callCreateKeyTx(ctx context.Context, tx pgx.Tx, actor, ws, keyID, sessID, name string,
	ttl time.Duration, seed string,
) ([]byte, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT mesh_ops.create_api_key_v1(`+memberActorArgsSQL+`,
    $2::UUID, $3::UUID, $4::UUID, $5, pg_catalog.transaction_timestamp() + ($6::BIGINT * interval '1 second'),
    'hmac-sha256-v1', 'api-key-v1', pg_catalog.sha256(pg_catalog.convert_to($7, 'UTF8')), pg_catalog.uuidv7())`+
		memberActorFromSQL+`WHERE session.public_id = $1::UUID`,
		actor, ws, keyID, sessID, name, int64(ttl/time.Second), seed).Scan(&raw)
	return raw, err
}

func mustCreateKeyTx(ctx context.Context, t *testing.T, tx pgx.Tx, actor, ws, keyID, sessID, name string,
	ttl time.Duration, seed string,
) []byte {
	t.Helper()
	raw, err := callCreateKeyTx(ctx, tx, actor, ws, keyID, sessID, name, ttl, seed)
	if err != nil {
		t.Fatalf("create_api_key_v1(%s): %v", name, err)
	}
	return raw
}

func callRevokeKeyTx(ctx context.Context, tx pgx.Tx, actor, ws, memberID, keyID string) ([]byte, error) {
	var memberArg any
	if memberID != "" {
		memberArg = memberID
	}
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT mesh_ops.revoke_api_key_v1(`+memberActorArgsSQL+`,
    $2::UUID, $3::UUID, $4::UUID, pg_catalog.uuidv7())`+memberActorFromSQL+
		`WHERE session.public_id = $1::UUID`, actor, ws, memberArg, keyID).Scan(&raw)
	return raw, err
}

func mustRevokeKeyTx(ctx context.Context, t *testing.T, tx pgx.Tx, actor, ws, memberID, keyID string) keyRevokeResultFixture {
	t.Helper()
	raw, err := callRevokeKeyTx(ctx, tx, actor, ws, memberID, keyID)
	if err != nil {
		t.Fatalf("revoke_api_key_v1(%s): %v", keyID, err)
	}
	if !bytes.Contains(raw, []byte(`"last_used_at"`)) {
		t.Errorf("revoke_api_key_v1 stripped last_used_at from key document: %s", string(raw))
	}
	var out keyRevokeResultFixture
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode revoke result: %v (%s)", err, string(raw))
	}
	return out
}

func callListKeysTx(ctx context.Context, tx pgx.Tx, actor, ws, memberID string,
	afterAt *time.Time, afterID string, limit int,
) ([]byte, error) {
	var memberArg, cursorAt, cursorID any
	if memberID != "" {
		memberArg = memberID
	}
	if afterAt != nil {
		cursorAt = *afterAt
		cursorID = afterID
	}
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT mesh_ops.list_api_keys_v1(`+memberActorArgsSQL+`,
    $2::UUID, $3::UUID, $4::TIMESTAMPTZ, $5::UUID, $6)`+memberActorFromSQL+
		`WHERE session.public_id = $1::UUID`, actor, ws, memberArg, cursorAt, cursorID, limit).Scan(&raw)
	return raw, err
}

func mustListKeysTx(ctx context.Context, t *testing.T, tx pgx.Tx, actor, ws, memberID string,
	afterAt *time.Time, afterID string, limit int,
) keyListPageFixture {
	t.Helper()
	raw, err := callListKeysTx(ctx, tx, actor, ws, memberID, afterAt, afterID, limit)
	if err != nil {
		t.Fatalf("list_api_keys_v1: %v", err)
	}
	var out keyListPageFixture
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode list result: %v (%s)", err, string(raw))
	}
	return out
}

func callReadKeyTx(ctx context.Context, tx pgx.Tx, actor, ws, keyID string) ([]byte, error) {
	var raw []byte
	err := tx.QueryRow(ctx, `SELECT mesh_ops.read_api_key_v1(`+memberActorArgsSQL+`,
    $2::UUID, $3::UUID)`+memberActorFromSQL+`WHERE session.public_id = $1::UUID`,
		actor, ws, keyID).Scan(&raw)
	return raw, err
}

func mustReadKeyTx(ctx context.Context, t *testing.T, tx pgx.Tx, actor, ws, keyID string) keyDocumentFixture {
	t.Helper()
	raw, err := callReadKeyTx(ctx, tx, actor, ws, keyID)
	if err != nil {
		t.Fatalf("read_api_key_v1: %v", err)
	}
	var wrapper struct {
		Key keyDocumentFixture `json:"key"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatalf("decode read result: %v (%s)", err, string(raw))
	}
	return wrapper.Key
}

func resolveKeyRowTx(ctx context.Context, t *testing.T, tx pgx.Tx, actor, keyID string) (int, string, string, *time.Time) {
	t.Helper()
	rows, err := tx.Query(ctx, `SELECT resolved.token_digest_algorithm, resolved.token_digest_key_id, resolved.last_used_at
FROM mesh.account_session AS s
JOIN mesh.deployment AS d ON d.id = s.deployment_id
CROSS JOIN LATERAL mesh_ops.resolve_api_key_v1(d.installation_public_id, d.recovery_epoch, $2::UUID) AS resolved
WHERE s.public_id = $1::UUID`, actor, keyID)
	if err != nil {
		t.Fatalf("resolve_api_key_v1: %v", err)
	}
	defer rows.Close()
	var count int
	var alg, kid string
	var lastUsed *time.Time
	for rows.Next() {
		count++
		if err := rows.Scan(&alg, &kid, &lastUsed); err != nil {
			t.Fatal(err)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return count, alg, kid, lastUsed
}

func touchKeyUsageTx(ctx context.Context, t *testing.T, tx pgx.Tx, actor, keyID string) bool {
	t.Helper()
	var touched bool
	if err := tx.QueryRow(ctx, `SELECT mesh_ops.touch_api_key_usage_v1(d.installation_public_id, $2::UUID)
FROM mesh.account_session AS s JOIN mesh.deployment AS d ON d.id = s.deployment_id
WHERE s.public_id = $1::UUID`, actor, keyID).Scan(&touched); err != nil {
		t.Fatalf("touch_api_key_usage_v1: %v", err)
	}
	return touched
}

func decodeCreatedKey(t *testing.T, raw []byte) keyDocumentFixture {
	t.Helper()
	if bytes.Contains(bytes.ToLower(raw), []byte("digest")) {
		t.Errorf("create_api_key_v1 leaked digest material: %s", string(raw))
	}
	if !bytes.Contains(raw, []byte(`"last_used_at"`)) {
		t.Errorf("create_api_key_v1 omitted last_used_at: %s", string(raw))
	}
	var wrapper struct {
		Key keyDocumentFixture `json:"key"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		t.Fatalf("decode create wrapper: %v (%s)", err, string(raw))
	}
	return wrapper.Key
}

func inSavepointTx(ctx context.Context, t *testing.T, tx pgx.Tx, fn func() error) error {
	t.Helper()
	if _, err := tx.Exec(ctx, `SAVEPOINT sp_call`); err != nil {
		t.Fatal(err)
	}
	callErr := fn()
	if callErr != nil {
		if _, rbErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT sp_call`); rbErr != nil {
			t.Fatal(rbErr)
		}
	} else {
		if _, relErr := tx.Exec(ctx, `RELEASE SAVEPOINT sp_call`); relErr != nil {
			t.Fatal(relErr)
		}
	}
	return callErr
}

func assertTxRefused(ctx context.Context, t *testing.T, tx pgx.Tx, name, code, msg, query string, args ...any) {
	t.Helper()
	if _, err := tx.Exec(ctx, `SAVEPOINT sp_refuse`); err != nil {
		t.Fatal(err)
	}
	_, err := tx.Exec(ctx, query, args...)
	assertPGError(t, name, err, code, msg)
	if _, rbErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT sp_refuse`); rbErr != nil {
		t.Fatal(rbErr)
	}
}

func assertPGError(t *testing.T, name string, err error, wantCode, wantMessage string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: succeeded, want SQLSTATE %s (%q)", name, wantCode, wantMessage)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("%s: non-PG error %v", name, err)
	}
	if pgErr.Code != wantCode || pgErr.Message != wantMessage {
		t.Errorf("%s: got SQLSTATE %s %q, want %s %q", name, pgErr.Code, pgErr.Message, wantCode, wantMessage)
	}
}

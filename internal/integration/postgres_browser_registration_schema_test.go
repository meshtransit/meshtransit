//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func assertBrowserRegistrationSchemaIsolation(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	for _, table := range []string{"network_membership", "browser_registration_intent"} {
		var rlsEnabled, rlsForced, runtimeSelect, runtimeInsert, workerSelect bool
		var owner string
		err := admin.QueryRow(ctx, `SELECT
    relation.relrowsecurity,
    relation.relforcerowsecurity,
    pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'SELECT'),
    pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'INSERT'),
    pg_catalog.has_table_privilege('mesh_worker', relation.oid, 'SELECT'),
    pg_catalog.pg_get_userbyid(relation.relowner)
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = 'mesh' AND relation.relname = $1`, table).Scan(
			&rlsEnabled, &rlsForced, &runtimeSelect, &runtimeInsert, &workerSelect, &owner,
		)
		if err != nil {
			t.Fatalf("read %s security catalog: %v", table, err)
		}
		if !rlsEnabled || !rlsForced || runtimeSelect || runtimeInsert || workerSelect || owner != "mesh_migrator" {
			t.Fatalf("%s exposed direct authority: rls=%v forced=%v runtime-read=%v runtime-write=%v worker-read=%v owner=%s",
				table, rlsEnabled, rlsForced, runtimeSelect, runtimeInsert, workerSelect, owner)
		}
	}
	var migratorPolicies, runtimePolicies int
	if err := admin.QueryRow(ctx, `SELECT
    pg_catalog.count(*) FILTER (WHERE 'mesh_migrator' = ANY(roles)),
    pg_catalog.count(*) FILTER (WHERE 'mesh_runtime' = ANY(roles))
FROM pg_catalog.pg_policies
WHERE schemaname='mesh' AND tablename='browser_registration_intent'`).Scan(
		&migratorPolicies, &runtimePolicies,
	); err != nil {
		t.Fatalf("read browser registration intent RLS policies: %v", err)
	}
	if migratorPolicies != 1 || runtimePolicies != 0 {
		t.Fatalf("browser intent policy exposure: migrator=%d runtime=%d", migratorPolicies, runtimePolicies)
	}
}

func assertBrowserRegistrationIntentIssue(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin browser intent issue fixture: %v", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	setIntegrationChange(ctx, t, transaction, "01890f00-0000-7000-8000-000000016300")

	const firstID = "01890f00-0000-7000-8000-000000016301"
	const retryID = "01890f00-0000-7000-8000-000000016302"
	var recoveryEpoch int64
	if err := transaction.QueryRow(ctx, `SELECT recovery_epoch
FROM mesh.deployment
WHERE installation_public_id='01890f00-0000-7000-8000-000000000001'::UUID`).Scan(&recoveryEpoch); err != nil {
		t.Fatalf("read current intent fixture recovery epoch: %v", err)
	}
	machineKey := bytes.Repeat([]byte{0x31}, 32)
	fingerprint := bytes.Repeat([]byte{0x32}, 32)
	nodeKey := bytes.Repeat([]byte{0x33}, 32)
	firstNonce := bytes.Repeat([]byte{0x34}, 32)
	firstDigest := bytes.Repeat([]byte{0x35}, 32)
	expiresAt := time.Now().Add(5 * time.Minute).UTC().Truncate(time.Microsecond)
	issue := func(id string, nonce, digest, node []byte) (string, []byte, []byte, string) {
		t.Helper()
		var issuedID, keyID, state string
		var issuedNonce, issuedDigest []byte
		var issuedEpoch int64
		var issuedExpiry time.Time
		if err := transaction.QueryRow(ctx, `SELECT
    intent_public_id::TEXT, issued_recovery_epoch, token_nonce,
    token_key_id, token_digest, intent_state, intent_expires_at
FROM mesh_ops.issue_browser_registration_intent_v1(
    '01890f00-0000-7000-8000-000000000001'::UUID, $8::BIGINT, $1::UUID,
    $2::BYTEA, $3::BYTEA, $4::BYTEA, 'browser-test-device'::TEXT,
    $5::BYTEA, 'browser-v1'::TEXT, $6::BYTEA, $7::TIMESTAMPTZ
)`, id, machineKey, fingerprint, node, nonce, digest, expiresAt, recoveryEpoch).Scan(
			&issuedID, &issuedEpoch, &issuedNonce, &keyID,
			&issuedDigest, &state, &issuedExpiry,
		); err != nil {
			t.Fatalf("issue browser intent: %v", err)
		}
		if issuedEpoch != recoveryEpoch || keyID != "browser-v1" || state != "pending" ||
			!issuedExpiry.Equal(expiresAt) {
			t.Fatalf("issued browser intent lost epoch/key/state/expiry: %d %s %s %s",
				issuedEpoch, keyID, state, issuedExpiry)
		}
		return issuedID, issuedNonce, issuedDigest, state
	}
	id, nonce, digest, _ := issue(firstID, firstNonce, firstDigest, nodeKey)
	if id != firstID || !bytes.Equal(nonce, firstNonce) || !bytes.Equal(digest, firstDigest) {
		t.Fatal("first browser intent did not persist exact token derivation evidence")
	}
	retryNonce := bytes.Repeat([]byte{0x36}, 32)
	retryDigest := bytes.Repeat([]byte{0x37}, 32)
	id, nonce, digest, _ = issue(retryID, retryNonce, retryDigest, nodeKey)
	if id != firstID || !bytes.Equal(nonce, firstNonce) || !bytes.Equal(digest, firstDigest) {
		t.Fatal("browser intent retry did not converge on persisted URL evidence")
	}
	var intentCount, auditCount int
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh.browser_registration_intent
WHERE machine_key_fingerprint=$1::BYTEA`, fingerprint).Scan(&intentCount); err != nil {
		t.Fatal(err)
	}
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_audit.authority_mutation
WHERE aggregate_kind='browser_registration_intent' AND row_public_id=$1::UUID`, firstID).Scan(&auditCount); err != nil {
		t.Fatal(err)
	}
	if intentCount != 1 || auditCount != 1 {
		t.Fatalf("browser intent retry created rows/audit entries: %d/%d", intentCount, auditCount)
	}
	readFollowupCount := func(token, machine, node []byte, hostname string, epoch int64) int {
		t.Helper()
		var count int
		if err := transaction.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.read_browser_registration_followup_v1(
    '01890f00-0000-7000-8000-000000000001'::UUID,
    $1::BIGINT, $2::BYTEA, $3::BYTEA, $4::BYTEA, $5::BYTEA, $6::TEXT
)`, epoch, token, machine, fingerprint, node, hostname).Scan(&count); err != nil {
			t.Fatalf("read browser registration followup: %v", err)
		}
		return count
	}
	if got := readFollowupCount(firstDigest, machineKey, nodeKey, "browser-test-device", recoveryEpoch); got != 1 {
		t.Fatalf("exact machine-bound followup count = %d, want 1", got)
	}
	wrongToken := bytes.Repeat([]byte{0x39}, 32)
	wrongMachine := bytes.Repeat([]byte{0x3a}, 32)
	wrongNode := bytes.Repeat([]byte{0x38}, 32)
	for _, mismatch := range []struct {
		name     string
		token    []byte
		machine  []byte
		node     []byte
		hostname string
		epoch    int64
	}{
		{name: "token", token: wrongToken, machine: machineKey, node: nodeKey, hostname: "browser-test-device", epoch: recoveryEpoch},
		{name: "machine", token: firstDigest, machine: wrongMachine, node: nodeKey, hostname: "browser-test-device", epoch: recoveryEpoch},
		{name: "Node", token: firstDigest, machine: machineKey, node: wrongNode, hostname: "browser-test-device", epoch: recoveryEpoch},
		{name: "hostname", token: firstDigest, machine: machineKey, node: nodeKey, hostname: "other-device", epoch: recoveryEpoch},
		{name: "recovery epoch", token: firstDigest, machine: machineKey, node: nodeKey, hostname: "browser-test-device", epoch: recoveryEpoch + 1},
	} {
		if got := readFollowupCount(mismatch.token, mismatch.machine, mismatch.node, mismatch.hostname, mismatch.epoch); got != 0 {
			t.Fatalf("mismatched %s read browser followup: %d", mismatch.name, got)
		}
	}
	var sessionKeyID string
	var sessionDigest []byte
	if err := transaction.QueryRow(ctx, `SELECT token_digest_key_id, token_digest
FROM mesh.account_session WHERE public_id=$1::UUID`, integrationManagementSessionPublicID).Scan(
		&sessionKeyID, &sessionDigest,
	); err != nil {
		t.Fatalf("read landing fixture Account Session: %v", err)
	}
	readLanding := func(token, session []byte, epoch int64) (string, string, string) {
		t.Helper()
		var id, state, hostname string
		err := transaction.QueryRow(ctx, `SELECT
    intent_public_id::TEXT, intent_state, requested_hostname
FROM mesh_ops.read_browser_registration_landing_v1(
    '01890f00-0000-7000-8000-000000000001'::UUID,
    $1::BIGINT, $2::TEXT, $3::BYTEA, $4::BYTEA
)`, epoch, sessionKeyID, session, token).Scan(&id, &state, &hostname)
		if err == pgx.ErrNoRows {
			return "", "", ""
		}
		if err != nil {
			t.Fatalf("read browser landing: %v", err)
		}
		return id, state, hostname
	}
	landingID, landingState, landingHostname := readLanding(firstDigest, sessionDigest, recoveryEpoch)
	if landingID != firstID || landingState != "pending" || landingHostname != "browser-test-device" {
		t.Fatalf("SSO-bound browser landing = %q/%q/%q", landingID, landingState, landingHostname)
	}
	wrongSession := bytes.Clone(sessionDigest)
	wrongSession[0] ^= 0xff
	for _, mismatch := range []struct {
		name    string
		token   []byte
		session []byte
		epoch   int64
	}{
		{name: "token", token: wrongToken, session: sessionDigest, epoch: recoveryEpoch},
		{name: "SSO session", token: firstDigest, session: wrongSession, epoch: recoveryEpoch},
		{name: "recovery epoch", token: firstDigest, session: sessionDigest, epoch: recoveryEpoch + 1},
	} {
		id, _, _ := readLanding(mismatch.token, mismatch.session, mismatch.epoch)
		if id != "" {
			t.Fatalf("mismatched %s received browser landing", mismatch.name)
		}
	}
	var restoredChangeID string
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.current_setting('mesh.change_public_id', TRUE)`).Scan(&restoredChangeID); err != nil ||
		restoredChangeID != "01890f00-0000-7000-8000-000000016300" {
		t.Fatalf("browser intent issue did not restore change context: %q, err=%v", restoredChangeID, err)
	}
	var runtimeExecute, workerExecute bool
	if err := transaction.QueryRow(ctx, `SELECT
    pg_catalog.has_function_privilege('mesh_runtime', procedure.oid, 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_worker', procedure.oid, 'EXECUTE')
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
WHERE namespace.nspname='mesh_ops'
  AND procedure.proname='issue_browser_registration_intent_v1'`).Scan(
		&runtimeExecute, &workerExecute,
	); err != nil || !runtimeExecute || workerExecute {
		t.Fatalf("browser intent issue execute privilege: runtime=%v worker=%v err=%v",
			runtimeExecute, workerExecute, err)
	}
	if _, err := transaction.Exec(ctx, `SAVEPOINT browser_intent_conflict`); err != nil {
		t.Fatal(err)
	}
	var conflictingID string
	err = transaction.QueryRow(ctx, `SELECT intent_public_id::TEXT
FROM mesh_ops.issue_browser_registration_intent_v1(
    '01890f00-0000-7000-8000-000000000001'::UUID, $8::BIGINT,
    $1::UUID, $2::BYTEA, $3::BYTEA, $4::BYTEA, 'browser-test-device'::TEXT,
    $5::BYTEA, 'browser-v1'::TEXT, $6::BYTEA, $7::TIMESTAMPTZ
)`, retryID, machineKey, fingerprint, wrongNode, retryNonce, retryDigest, expiresAt, recoveryEpoch).Scan(&conflictingID)
	if err == nil {
		t.Fatal("browser intent accepted a Node-key change on the same machine")
	}
	if _, rollbackErr := transaction.Exec(ctx, `ROLLBACK TO SAVEPOINT browser_intent_conflict`); rollbackErr != nil {
		t.Fatal(rollbackErr)
	}
}

func assertBrowserEnrollmentNetworkChoices(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin browser Network choice fixture: %v", err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	setIntegrationChange(ctx, t, transaction, "01890f00-0000-7000-8000-000000016000")

	var digestKeyID string
	var digest []byte
	var deploymentPublicID string
	var recoveryEpoch int64
	if err := transaction.QueryRow(ctx, `SELECT
    session.token_digest_key_id, session.token_digest,
    deployment.installation_public_id, deployment.recovery_epoch
FROM mesh.account_session AS session
JOIN mesh.deployment AS deployment ON deployment.id=session.deployment_id
WHERE session.public_id=$1::UUID`, integrationManagementSessionPublicID).Scan(
		&digestKeyID, &digest, &deploymentPublicID, &recoveryEpoch,
	); err != nil {
		t.Fatalf("read fixture Account Session digest: %v", err)
	}
	var admittedCount int
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.resolve_account_session_v2($1::UUID,$2::BIGINT,'hmac-sha256-v1',$3::TEXT,$4::BYTEA)`,
		deploymentPublicID, recoveryEpoch, digestKeyID, digest,
	).Scan(&admittedCount); err != nil || admittedCount != 1 {
		t.Fatalf("fixture Account Session failed strict resolution: count=%d err=%v", admittedCount, err)
	}
	var admittedWorkspace *string
	if err := transaction.QueryRow(ctx, `SELECT login_workspace_public_id::TEXT
FROM mesh_ops.resolve_account_session_v2($1::UUID,$2::BIGINT,'hmac-sha256-v1',$3::TEXT,$4::BYTEA)`,
		deploymentPublicID, recoveryEpoch, digestKeyID, digest,
	).Scan(&admittedWorkspace); err != nil || admittedWorkspace == nil {
		t.Fatalf("fixture Account Session has no admitted Workspace: %v", err)
	}
	var joinedCount int
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.resolve_account_session_v2($1::UUID,$2::BIGINT,'hmac-sha256-v1',$3::TEXT,$4::BYTEA) AS admitted
JOIN mesh.account_session AS session
  ON session.public_id=admitted.session_public_id
 AND session.version=admitted.session_version
 AND session.principal_authority_generation=admitted.principal_authority_generation
 AND session.account_session_generation=admitted.account_session_generation
 AND session.provider_generation=admitted.provider_generation
 AND session.deployment_recovery_epoch=admitted.deployment_recovery_epoch
 AND session.state='active'
 AND session.idle_expires_at>pg_catalog.transaction_timestamp()
 AND session.absolute_expires_at>pg_catalog.transaction_timestamp()
JOIN mesh.workspace AS workspace
  ON workspace.deployment_id=session.deployment_id
 AND workspace.id=session.login_workspace_id
 AND workspace.public_id=admitted.login_workspace_public_id
 AND workspace.state='active'
 AND workspace.deleted_at IS NULL`, deploymentPublicID, recoveryEpoch, digestKeyID, digest,
	).Scan(&joinedCount); err != nil || joinedCount != 1 {
		t.Fatalf("admitted Session lost Workspace join: count=%d workspace=%s err=%v",
			joinedCount, *admittedWorkspace, err)
	}
	readChoices := func(keyID string, value []byte) *string {
		t.Helper()
		var output *string
		if err := transaction.QueryRow(ctx, `SELECT mesh_ops.list_browser_enrollment_networks_v1(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, NULL::UUID, 100
)::TEXT`, deploymentPublicID, recoveryEpoch, keyID, value).Scan(&output); err != nil {
			t.Fatalf("read browser Network choices: %v", err)
		}
		return output
	}
	readNetworkIDs := func(output *string) []string {
		t.Helper()
		if output == nil {
			t.Fatal("active Session lost browser Network choice result")
		}
		var page struct {
			WorkspaceID string `json:"workspace_id"`
			Networks    []struct {
				NetworkID string `json:"network_id"`
			} `json:"networks"`
		}
		if err := json.Unmarshal([]byte(*output), &page); err != nil ||
			page.WorkspaceID != "01890f00-0000-7000-8000-000000000103" {
			t.Fatalf("invalid browser Network choice result: %v", err)
		}
		ids := make([]string, 0, len(page.Networks))
		for _, choice := range page.Networks {
			ids = append(ids, choice.NetworkID)
		}
		return ids
	}
	for name, value := range map[string]string{
		"mesh.requested_workspace_public_id":                 "01890f00-0000-7000-8000-000000000104",
		"mesh.browser_enrollment_choice_workspace_public_id": "01890f00-0000-7000-8000-000000000104",
	} {
		if _, err := transaction.Exec(ctx, `SELECT pg_catalog.set_config($1::TEXT, $2::TEXT, TRUE)`, name, value); err != nil {
			t.Fatalf("set hostile caller scope %s: %v", name, err)
		}
	}
	if ids := readNetworkIDs(readChoices(digestKeyID, digest)); len(ids) != 0 {
		t.Fatalf("Session without Network membership received choices: %v", ids)
	}
	for name, want := range map[string]string{
		"mesh.requested_workspace_public_id":                 "01890f00-0000-7000-8000-000000000104",
		"mesh.browser_enrollment_choice_workspace_public_id": "01890f00-0000-7000-8000-000000000104",
	} {
		var got string
		if err := transaction.QueryRow(ctx, `SELECT pg_catalog.current_setting($1::TEXT, TRUE)`, name).Scan(&got); err != nil || got != want {
			t.Fatalf("browser chooser did not restore caller scope %s: got=%q err=%v", name, got, err)
		}
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO mesh.enrollment_profile (
    id, public_id, workspace_id, network_id, created_by_principal_id,
    display_name, name_key, node_lifetime_seconds, ephemeral_mode,
    credential_use_policy, state, interactive_authorization_enabled
) OVERRIDING SYSTEM VALUE VALUES (
    1601, '01890f00-0000-7000-8000-000000001601', 103, 203, 11,
    'Browser login profile', 'browser-login-profile', 3600, 'persistent',
    'unlimited', 'active', TRUE
)`); err != nil {
		t.Fatalf("seed explicit interactive Enrollment Profile: %v", err)
	}
	if ids := readNetworkIDs(readChoices(digestKeyID, digest)); len(ids) != 0 {
		t.Fatalf("profile alone granted Network choice: %v", ids)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO mesh.network_membership (
    id, public_id, deployment_id, workspace_id, network_id,
    principal_id, workspace_membership_id, state, valid_from
) OVERRIDING SYSTEM VALUE VALUES (
    1602, '01890f00-0000-7000-8000-000000001602', 1, 103, 203,
    11, 841, 'active', pg_catalog.transaction_timestamp() - INTERVAL '1 minute'
	)`); err != nil {
		t.Fatalf("seed explicit Network membership: %v", err)
	}
	assertBrowserApprovalAuthority(ctx, t, transaction, deploymentPublicID,
		recoveryEpoch, digestKeyID, digest)
	ids := readNetworkIDs(readChoices(digestKeyID, digest))
	if len(ids) != 1 || ids[0] != "01890f00-0000-7000-8000-000000000203" {
		t.Fatalf("exact eligible Network choices = %v", ids)
	}
	wrongDigest := make([]byte, len(digest))
	copy(wrongDigest, digest)
	wrongDigest[0] ^= 0xff
	if output := readChoices(digestKeyID, wrongDigest); output != nil {
		t.Fatal("invalid Account Session digest received Network inventory")
	}
	if _, err := transaction.Exec(ctx, `UPDATE mesh.network_membership
SET state='suspended', authority_generation=authority_generation+1,
    version=version+1, updated_at=pg_catalog.clock_timestamp()
WHERE id=1602`); err != nil {
		t.Fatalf("suspend Network membership: %v", err)
	}
	if ids := readNetworkIDs(readChoices(digestKeyID, digest)); len(ids) != 0 {
		t.Fatalf("suspended Network membership retained choice: %v", ids)
	}
	var approvalCount int
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.lock_browser_registration_approval_authority_v1(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, $5::BYTEA,
    '01890f00-0000-7000-8000-000000000203'::UUID
)`, deploymentPublicID, recoveryEpoch, digestKeyID, digest,
		bytes.Repeat([]byte{0x65}, 32)).Scan(&approvalCount); err != nil || approvalCount != 0 {
		t.Fatalf("suspended membership approval authority: count=%d err=%v", approvalCount, err)
	}
	if _, err := transaction.Exec(ctx, `UPDATE mesh.network_membership
SET state='active', authority_generation=authority_generation+1,
    version=version+1, updated_at=pg_catalog.clock_timestamp()
WHERE id=1602`); err != nil {
		t.Fatalf("restore Network membership for profile denial: %v", err)
	}
	if _, err := transaction.Exec(ctx, `UPDATE mesh.enrollment_profile
SET interactive_authorization_enabled=FALSE,
    version=version+1, updated_at=pg_catalog.clock_timestamp()
WHERE id=1601`); err != nil {
		t.Fatalf("disable interactive Enrollment Profile: %v", err)
	}
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.lock_browser_registration_approval_authority_v1(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, $5::BYTEA,
    '01890f00-0000-7000-8000-000000000203'::UUID
)`, deploymentPublicID, recoveryEpoch, digestKeyID, digest,
		bytes.Repeat([]byte{0x65}, 32)).Scan(&approvalCount); err != nil || approvalCount != 0 {
		t.Fatalf("disabled profile approval authority: count=%d err=%v", approvalCount, err)
	}
	var runtimeExecute, workerExecute bool
	if err := transaction.QueryRow(ctx, `SELECT
    pg_catalog.has_function_privilege('mesh_runtime', procedure.oid, 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_worker', procedure.oid, 'EXECUTE')
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
WHERE namespace.nspname='mesh_ops'
  AND procedure.proname='list_browser_enrollment_networks_v1'`).Scan(
		&runtimeExecute, &workerExecute,
	); err != nil || !runtimeExecute || workerExecute {
		t.Fatalf("browser Network chooser execute privilege: runtime=%v worker=%v err=%v",
			runtimeExecute, workerExecute, err)
	}
}

func assertBrowserApprovalAuthority(
	ctx context.Context, t *testing.T, transaction pgx.Tx,
	deploymentID string, recoveryEpoch int64, digestKeyID string, sessionDigest []byte,
) {
	t.Helper()
	const intentID = "01890f00-0000-7000-8000-000000016601"
	const chosenNetwork = "01890f00-0000-7000-8000-000000000203"
	tokenDigest := bytes.Repeat([]byte{0x65}, 32)
	var issued string
	if err := transaction.QueryRow(ctx, `SELECT intent_public_id::TEXT
FROM mesh_ops.issue_browser_registration_intent_v1(
    $1::UUID, $2::BIGINT, $3::UUID, $4::BYTEA, $5::BYTEA,
    $6::BYTEA, 'browser-approval-device'::TEXT, $7::BYTEA,
    'browser-v1'::TEXT, $8::BYTEA, $9::TIMESTAMPTZ
)`, deploymentID, recoveryEpoch, intentID,
		bytes.Repeat([]byte{0x61}, 32), bytes.Repeat([]byte{0x62}, 32),
		bytes.Repeat([]byte{0x63}, 32), bytes.Repeat([]byte{0x64}, 32),
		tokenDigest, time.Now().Add(5*time.Minute).UTC(),
	).Scan(&issued); err != nil || issued != intentID {
		t.Fatalf("seed browser approval intent: id=%q err=%v", issued, err)
	}
	resolve := func(session, token []byte, chosen string) int {
		t.Helper()
		var count int
		if err := transaction.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.lock_browser_registration_approval_authority_v1(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, $5::BYTEA, $6::UUID
)`, deploymentID, recoveryEpoch, digestKeyID, session, token, chosen).Scan(&count); err != nil {
			t.Fatalf("lock browser approval authority: %v", err)
		}
		return count
	}
	wrongSession := bytes.Clone(sessionDigest)
	wrongSession[0] ^= 0xff
	wrongToken := bytes.Clone(tokenDigest)
	wrongToken[0] ^= 0xff
	for _, test := range []struct {
		name    string
		session []byte
		token   []byte
		network string
	}{
		{name: "SSO session", session: wrongSession, token: tokenDigest, network: chosenNetwork},
		{name: "URL token", session: sessionDigest, token: wrongToken, network: chosenNetwork},
	} {
		if count := resolve(test.session, test.token, test.network); count != 0 {
			t.Fatalf("%s reached approval authority: %d", test.name, count)
		}
	}
	if _, err := transaction.Exec(ctx, `SAVEPOINT browser_approval_ineligible_network`); err != nil {
		t.Fatal(err)
	}
	if count := resolve(sessionDigest, tokenDigest,
		"01890f00-0000-7000-8000-000000000204"); count != 0 {
		t.Fatalf("ineligible Network reached approval authority: %d", count)
	}
	if _, err := transaction.Exec(ctx, `ROLLBACK TO SAVEPOINT browser_approval_ineligible_network`); err != nil {
		t.Fatal(err)
	}
	if count := resolve(sessionDigest, tokenDigest, chosenNetwork); count != 1 {
		t.Fatalf("exact Session/intent/Network approval authority = %d, want 1", count)
	}
	if _, err := transaction.Exec(ctx, `SAVEPOINT browser_approval_record`); err != nil {
		t.Fatal(err)
	}
	const registrationID = "01890f00-0000-7000-8000-000000016702"
	var recordedID, recordedIntent, recordedSession, recordedPrincipal string
	var recordedVersion, recordedRevision int64
	var recordedHash []byte
	if err := transaction.QueryRow(ctx, `SELECT
    approved_registration_public_id::TEXT, approved_registration_version,
    approved_intent_public_id::TEXT, approved_session_public_id::TEXT,
    approved_principal_public_id::TEXT, approved_network_revision,
    approved_request_hash
FROM mesh_ops.record_browser_registration_approval_v1(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, $5::BYTEA,
    $6::UUID, $7::UUID, $8::UUID
)`, deploymentID, recoveryEpoch, digestKeyID, sessionDigest,
		tokenDigest, chosenNetwork, registrationID,
		"01890f00-0000-7000-8000-000000016703",
	).Scan(&recordedID, &recordedVersion, &recordedIntent, &recordedSession,
		&recordedPrincipal, &recordedRevision, &recordedHash); err != nil {
		t.Fatalf("record browser Network approval: %v", err)
	}
	if recordedID != registrationID || recordedVersion != 1 ||
		recordedIntent != intentID || recordedSession != integrationManagementSessionPublicID ||
		recordedPrincipal == "" || recordedRevision <= 0 || len(recordedHash) != 32 {
		t.Fatalf("browser approval record lost authority: registration=%s intent=%s session=%s principal=%s version=%d revision=%d hash=%d",
			recordedID, recordedIntent, recordedSession, recordedPrincipal,
			recordedVersion, recordedRevision, len(recordedHash))
	}
	var pendingState, intentState, approvalSession string
	if err := transaction.QueryRow(ctx, `SELECT registration.state, intent.state,
    intent.approved_session_public_id::TEXT
FROM mesh.pending_registration AS registration
JOIN mesh.browser_registration_intent AS intent
  ON intent.pending_registration_public_id = registration.public_id
WHERE registration.public_id=$1::UUID
  AND registration.authorization_kind='interactive'
  AND registration.authorized_principal_id IS NOT NULL
  AND registration.request_hash=$2::BYTEA`, registrationID, recordedHash).Scan(
		&pendingState, &intentState, &approvalSession,
	); err != nil || pendingState != "authorized" || intentState != "approved" ||
		approvalSession != integrationManagementSessionPublicID {
		t.Fatalf("approval state was not atomic: registration=%s intent=%s session=%s err=%v",
			pendingState, intentState, approvalSession, err)
	}
	if _, err := transaction.Exec(ctx, `SAVEPOINT browser_approval_session_tamper`); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, `UPDATE mesh.browser_registration_intent
SET approved_session_public_id=NULL, version=version+1,
    updated_at=pg_catalog.clock_timestamp()
WHERE public_id=$1::UUID`, intentID); err == nil {
		t.Fatal("approved browser Session could be removed")
	}
	if _, err := transaction.Exec(ctx, `ROLLBACK TO SAVEPOINT browser_approval_session_tamper`); err != nil {
		t.Fatal(err)
	}
	var retryCount int
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.record_browser_registration_approval_v1(
    $1::UUID, $2::BIGINT, $3::TEXT, $4::BYTEA, $5::BYTEA,
    $6::UUID, $7::UUID, $8::UUID
)`, deploymentID, recoveryEpoch, digestKeyID, sessionDigest,
		tokenDigest, chosenNetwork,
		"01890f00-0000-7000-8000-000000016704",
		"01890f00-0000-7000-8000-000000016705").Scan(&retryCount); err != nil || retryCount != 0 {
		t.Fatalf("approval replay created another record: count=%d err=%v", retryCount, err)
	}
	if _, err := transaction.Exec(ctx, `ROLLBACK TO SAVEPOINT browser_approval_record`); err != nil {
		t.Fatal(err)
	}
	var runtimeExecute, workerExecute bool
	if err := transaction.QueryRow(ctx, `SELECT
    pg_catalog.has_function_privilege('mesh_runtime', procedure.oid, 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_worker', procedure.oid, 'EXECUTE')
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=procedure.pronamespace
WHERE namespace.nspname='mesh_ops'
  AND procedure.proname='lock_browser_registration_approval_authority_v1'`).Scan(
		&runtimeExecute, &workerExecute,
	); err != nil || !runtimeExecute || workerExecute {
		t.Fatalf("browser approval lock execute privilege: runtime=%v worker=%v err=%v",
			runtimeExecute, workerExecute, err)
	}
}

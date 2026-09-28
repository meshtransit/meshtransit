//go:build integration

package main

import (
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/config"
)

const (
	transitionIntegrationDeploymentID = "01890f00-0000-7000-8000-000000000001"
	transitionIntegrationActorID      = "01890f00-0000-7000-8000-000000000011"
	transitionIntegrationMigrationID  = "01890f40-0000-7000-8000-000000000001"
	transitionIntegrationSourceID     = "01890f40-0000-7000-8000-000000000010"
	transitionIntegrationTargetID     = "01890f40-0000-7000-8000-000000000020"
	transitionIntegrationPrincipalID  = "01890f40-0000-7000-8000-000000000030"
	transitionIntegrationAccountID    = "01890f40-0000-7000-8000-000000000031"
	transitionIntegrationSubjectID    = "01890f40-0000-7000-8000-000000000032"
	transitionIntegrationSessionID    = "01890f40-0000-7000-8000-000000000033"
	transitionIntegrationAuthID       = "01890f40-0000-7000-8000-000000000034"
	transitionIntegrationSourceIssuer = "https://transition-source.example.test"
	transitionIntegrationTargetIssuer = "https://transition-target.example.test"
)

func TestIdentitySubjectTransitionPlan(t *testing.T) {
	if os.Getenv("MESHTRANSIT_IDENTITY_SUBJECT_TRANSITION_INTEGRATION") != "1" {
		t.Skip("identity subject transition integration fixture is disabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	database := transitionIntegrationDatabase(t)
	connection, err := openAdminDatabase(ctx, database)
	if err != nil {
		t.Fatalf("open transition fixture database: %v", err)
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer closeCancel()
		if err := connection.Close(closeCtx); err != nil {
			t.Errorf("close transition fixture database: %v", err)
		}
	}()

	manifest := transitionIntegrationManifest()
	spec, err := buildPlanSpec(
		manifest,
		strings.Repeat("a", 64),
		testSubjectKey(t, "transition-source-v1", 0x11),
		testSubjectKey(t, "transition-target-v1", 0x22),
	)
	if err != nil {
		t.Fatalf("build transition fixture plan: %v", err)
	}
	defer spec.clear()
	seedTransitionIntegrationFixture(ctx, t, connection, spec)
	assertTransitionIntegrationPlanState(ctx, t, connection, spec)

	before := loadTransitionIntegrationSnapshot(ctx, t, connection)
	output, err := executePlan(ctx, spec, database)
	if err != nil {
		t.Fatalf("execute exact transition plan: %v", err)
	}
	if output.Operation != "validated" || output.MappingCount != 1 ||
		output.ActiveSourceSubjectCount != 1 || output.ActiveSessionCount != 1 ||
		output.OpenAuthTransactionCount != 1 {
		t.Fatalf("transition plan output = %+v, want exact fixture counts", output)
	}
	after := loadTransitionIntegrationSnapshot(ctx, t, connection)
	if after != before {
		t.Fatal("validated transition plan mutated PostgreSQL state")
	}

	stale := spec
	stale.manifest.ExpectedActiveSessions = 0
	if _, err := executePlan(ctx, stale, database); err == nil {
		t.Fatal("stale transition plan was accepted")
	}
	if rejected := loadTransitionIntegrationSnapshot(ctx, t, connection); rejected != before {
		t.Fatal("rejected transition plan mutated PostgreSQL state")
	}
}

func assertTransitionIntegrationPlanState(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	spec planSpec,
) {
	t.Helper()
	transaction, err := connection.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.Serializable, AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		t.Fatalf("begin transition fixture assertion: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	if _, err := transaction.Exec(ctx, configurePlanSQL); err != nil {
		t.Fatalf("configure transition fixture assertion: %v", err)
	}
	state, err := loadAuthorityState(ctx, transaction, spec)
	if err != nil {
		t.Fatalf("load transition fixture authority: %v", err)
	}
	if !state.matches(spec) {
		t.Fatalf(
			"transition fixture authority mismatch: deployment=%s/%s actor=%s/%s source=%s/%s/%d/%d target=%s/%s/%d/%d",
			state.deploymentRecoveryState,
			state.deploymentState,
			state.actorKind,
			state.actorState,
			state.source.recoveryState,
			state.source.state,
			state.source.version,
			state.source.generationVersion,
			state.target.recoveryState,
			state.target.state,
			state.target.version,
			state.target.generationVersion,
		)
	}
	subjects, err := loadActiveSourceSubjects(
		ctx,
		transaction,
		state.deploymentInternalID,
		state.source.internalID,
	)
	if err != nil {
		t.Fatalf("load transition fixture subjects: %v", err)
	}
	if !subjectsMatchPlan(subjects, spec) {
		t.Fatalf("transition fixture subject mismatch: rows=%d", len(subjects))
	}
	collision, err := targetCollision(
		ctx,
		transaction,
		state.deploymentInternalID,
		state.target.internalID,
		spec,
	)
	if err != nil || collision {
		t.Fatalf("transition fixture target collision: collision=%t error=%v", collision, err)
	}
	for name, query := range map[string]string{
		"sessions": loadActiveSessionIDsSQL,
		"auth":     loadOpenAuthTransactionIDsSQL,
	} {
		count, err := countBoundedRows(
			ctx,
			transaction,
			query,
			state.deploymentInternalID,
			state.source.internalID,
			maximumActiveSessions+1,
		)
		if err != nil || count != 1 {
			t.Fatalf("transition fixture %s count=%d error=%v", name, count, err)
		}
	}
}

func transitionIntegrationDatabase(t *testing.T) databaseSettings {
	t.Helper()
	passwordFile, err := config.NewSecretFile(
		os.Getenv("MESHTRANSIT_TEST_POSTGRES_ADMIN_PASSWORD_FILE"),
	)
	if err != nil {
		t.Fatalf("load transition fixture password reference: %v", err)
	}
	trustFile, err := config.NewTrustFile(os.Getenv("MESHTRANSIT_POSTGRES_CA_FILE"))
	if err != nil {
		t.Fatalf("load transition fixture trust reference: %v", err)
	}
	return databaseSettings{
		address:      os.Getenv("MESHTRANSIT_POSTGRES_ADDRESS"),
		database:     os.Getenv("MESHTRANSIT_POSTGRES_DATABASE"),
		user:         "postgres",
		passwordFile: passwordFile,
		trustFile:    trustFile,
	}
}

func transitionIntegrationManifest() transitionManifest {
	return transitionManifest{
		SchemaVersion:    manifestSchemaVersion,
		MigrationID:      transitionIntegrationMigrationID,
		DeploymentID:     transitionIntegrationDeploymentID,
		ActorPrincipalID: transitionIntegrationActorID,
		Source: providerReference{
			ProviderID: transitionIntegrationSourceID, Issuer: transitionIntegrationSourceIssuer,
			SubjectKeyID: "transition-source-v1", ExpectedGeneration: 1,
			ExpectedGenerationVersion: 1, ExpectedProviderVersion: 1,
		},
		Target: providerReference{
			ProviderID: transitionIntegrationTargetID, Issuer: transitionIntegrationTargetIssuer,
			SubjectKeyID: "transition-target-v1", ExpectedGeneration: 1,
			ExpectedGenerationVersion: 1, ExpectedProviderVersion: 1,
		},
		ExpectedActiveSourceSubjects: 1,
		ExpectedActiveSessions:       1,
		ExpectedOpenAuthTransactions: 1,
		Mappings: []subjectMapping{{
			SourceSubjectID:       transitionIntegrationSubjectID,
			PrincipalID:           transitionIntegrationPrincipalID,
			ExpectedSourceVersion: 1, ExpectedClaimsRevision: 1,
			SourceSubject: "source-subject-exact", TargetSubject: "target-subject-exact",
		}},
	}
}

func seedTransitionIntegrationFixture(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	spec planSpec,
) {
	t.Helper()
	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin transition fixture: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.Background()) }()
	if _, err := transaction.Exec(
		ctx,
		"SELECT pg_catalog.set_config('mesh.change_public_id', $1, TRUE)",
		"01890f41-0000-7000-8000-000000000001",
	); err != nil {
		t.Fatalf("set transition fixture change: %v", err)
	}

	sourceDigest := spec.mappings[0].sourceDigest.Bytes()
	statements := []struct {
		name      string
		query     string
		arguments []any
	}{
		{name: "source provider", query: `INSERT INTO mesh.identity_provider (
    id, public_id, deployment_id, issuer, issuer_digest_algorithm, issuer_digest_key_id,
    issuer_digest, protocol, authority_kind, discovery_uri, authorization_endpoint,
    token_endpoint, jwks_uri, current_generation, recovery_state, state
) OVERRIDING SYSTEM VALUE VALUES (
    9601, $1::UUID, 1, $2, 'hmac-sha256-v1', 'transition-issuer-v1',
    pg_catalog.decode(pg_catalog.repeat('11', 32), 'hex'), 'oidc', 'external_oidc',
    $2 || '/.well-known/openid-configuration', $2 || '/authorize', $2 || '/token',
    $2 || '/keys', 1, 'verified', 'active'
)`, arguments: []any{transitionIntegrationSourceID, transitionIntegrationSourceIssuer}},
		{name: "source generation", query: `INSERT INTO mesh.identity_provider_generation (
    id, public_id, deployment_id, identity_provider_id, generation,
    trust_configuration_semantic_hash, recovery_mode, valid_from, state
) OVERRIDING SYSTEM VALUE VALUES (
    9611, '01890f40-0000-7000-8000-000000000011', 1, 9601, 1,
    pg_catalog.decode(pg_catalog.repeat('12', 32), 'hex'), 'initial',
    pg_catalog.transaction_timestamp(), 'current'
)`},
		{name: "source client", query: `INSERT INTO mesh.identity_provider_client (
    id, public_id, deployment_id, identity_provider_id, client_kind, client_id,
    allowed_flows, allowed_scopes, allowed_algorithms, redirect_uris,
    post_logout_redirect_uris, pkce_s256_required, client_auth_method,
    credential_reference, state
) OVERRIDING SYSTEM VALUE VALUES (
    9631, '01890f40-0000-7000-8000-000000000012', 1, 9601, 'confidential',
    'transition-source', ARRAY['authorization_code'], ARRAY['openid'], ARRAY['RS256'],
    ARRAY['https://transition.example.test/source/callback'], ARRAY[]::TEXT[], TRUE,
    'client_secret_basic', 'secret://transition/source', 'active'
)`},
		{name: "target provider", query: `INSERT INTO mesh.identity_provider (
    id, public_id, deployment_id, issuer, issuer_digest_algorithm, issuer_digest_key_id,
    issuer_digest, protocol, authority_kind, discovery_uri, authorization_endpoint,
    token_endpoint, jwks_uri, current_generation, recovery_state, state
) OVERRIDING SYSTEM VALUE VALUES (
    9602, $1::UUID, 1, $2, 'hmac-sha256-v1', 'transition-issuer-v1',
    pg_catalog.decode(pg_catalog.repeat('21', 32), 'hex'), 'oidc', 'managed_oidc',
    $2 || '/.well-known/openid-configuration', $2 || '/authorize', $2 || '/token',
    $2 || '/keys', 1, 'verified', 'active'
)`, arguments: []any{transitionIntegrationTargetID, transitionIntegrationTargetIssuer}},
		{name: "target generation", query: `INSERT INTO mesh.identity_provider_generation (
    id, public_id, deployment_id, identity_provider_id, generation,
    trust_configuration_semantic_hash, recovery_mode, valid_from, state
) OVERRIDING SYSTEM VALUE VALUES (
    9621, '01890f40-0000-7000-8000-000000000021', 1, 9602, 1,
    pg_catalog.decode(pg_catalog.repeat('22', 32), 'hex'), 'initial',
    pg_catalog.transaction_timestamp(), 'current'
)`},
		{name: "target client", query: `INSERT INTO mesh.identity_provider_client (
    id, public_id, deployment_id, identity_provider_id, client_kind, client_id,
    allowed_flows, allowed_scopes, allowed_algorithms, redirect_uris,
    post_logout_redirect_uris, pkce_s256_required, client_auth_method,
    credential_reference, state
) OVERRIDING SYSTEM VALUE VALUES (
    9632, '01890f40-0000-7000-8000-000000000022', 1, 9602, 'confidential',
    'transition-target', ARRAY['authorization_code'], ARRAY['openid'], ARRAY['RS256'],
    ARRAY['https://transition.example.test/target/callback'], ARRAY[]::TEXT[], TRUE,
    'client_secret_basic', 'secret://transition/target', 'active'
)`},
		{name: "principal", query: `INSERT INTO mesh.principal (
    id, public_id, deployment_id, kind, state
) OVERRIDING SYSTEM VALUE VALUES (9701, $1::UUID, 1, 'account', 'active')`,
			arguments: []any{transitionIntegrationPrincipalID}},
		{name: "account", query: `INSERT INTO mesh.account (
    id, public_id, deployment_id, principal_id, display_name,
    login_identifier_digest_algorithm, login_identifier_digest_key_id,
    login_identifier_digest, session_generation, recovery_state
) OVERRIDING SYSTEM VALUE VALUES (
    9701, $1::UUID, 1, 9701, 'Transition Fixture', 'hmac-sha256-v1',
    'transition-login-v1', pg_catalog.decode(pg_catalog.repeat('31', 32), 'hex'),
    1, 'verified'
)`, arguments: []any{transitionIntegrationAccountID}},
		{name: "source subject", query: `INSERT INTO mesh.identity_subject (
    id, public_id, deployment_id, identity_provider_id, principal_id,
    subject_digest_algorithm, subject_digest_key_id, subject_digest,
    claims_revision, last_seen_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    9711, $1::UUID, 1, 9601, 9701, 'hmac-sha256-v1', $2, $3,
    1, pg_catalog.transaction_timestamp(), 'active'
)`, arguments: []any{
			transitionIntegrationSubjectID,
			spec.mappings[0].sourceDigest.KeyID().String(),
			sourceDigest[:],
		}},
		{name: "active session", query: `INSERT INTO mesh.account_session (
    id, public_id, deployment_id, principal_id, identity_provider_id,
    identity_subject_id, identity_provider_client_id, login_workspace_id,
    token_digest_algorithm, token_digest_key_id, token_digest, provider_generation,
    authentication_time, amr, principal_authority_generation,
    account_session_generation, deployment_recovery_epoch, issued_at, last_used_at,
    idle_expires_at, absolute_expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    9811, $1::UUID, 1, 9701, 9601, 9711, 9631, 101,
    'hmac-sha256-v1', 'transition-session-v1',
    pg_catalog.decode(pg_catalog.repeat('32', 32), 'hex'), 1,
    pg_catalog.transaction_timestamp() - INTERVAL '1 minute', ARRAY['pwd'], 1, 1, 1,
    pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp(),
    pg_catalog.transaction_timestamp() + INTERVAL '30 minutes',
    pg_catalog.transaction_timestamp() + INTERVAL '8 hours', 'active'
)`, arguments: []any{transitionIntegrationSessionID}},
		{name: "pending authentication", query: `INSERT INTO mesh.auth_transaction (
    id, public_id, deployment_id, workspace_id, identity_provider_id,
    identity_provider_client_id, principal_id, flow_kind, operation_kind,
    operation_semantic_hash, state_digest_algorithm, state_digest_key_id, state_digest,
    nonce_digest_algorithm, nonce_digest_key_id, nonce_digest,
    pkce_verifier_encryption_algorithm, pkce_verifier_encryption_key_id,
    pkce_verifier_ciphertext, redirect_id, return_route_id, provider_generation,
    deployment_recovery_epoch, account_session_generation, expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    9801, $1::UUID, 1, 101, 9601, 9631, 9701,
    'browser_authorization_code', 'identity_link',
    pg_catalog.decode(pg_catalog.repeat('33', 32), 'hex'),
    'hmac-sha256-v1', 'transition-state-v1',
    pg_catalog.decode(pg_catalog.repeat('34', 32), 'hex'),
    'hmac-sha256-v1', 'transition-nonce-v1',
    pg_catalog.decode(pg_catalog.repeat('35', 32), 'hex'),
    'aead-aes-256-gcm-v1', 'transition-aead-v1',
    pg_catalog.decode(pg_catalog.repeat('36', 96), 'hex'),
    'transition-callback', 'workspace-home', 1, 1, 1,
    pg_catalog.transaction_timestamp() + INTERVAL '10 minutes', 'pending'
)`, arguments: []any{transitionIntegrationAuthID}},
	}
	for _, statement := range statements {
		if _, err := transaction.Exec(ctx, statement.query, statement.arguments...); err != nil {
			t.Fatalf("insert transition fixture %s: %v", statement.name, err)
		}
	}
	appendTransitionIntegrationEvidence(ctx, t, transaction)
	if err := transaction.Commit(ctx); err != nil {
		t.Fatalf("commit transition fixture: %v", err)
	}
}

func appendTransitionIntegrationEvidence(ctx context.Context, t *testing.T, transaction pgx.Tx) {
	t.Helper()
	var sequence int64
	var previousHash []byte
	if err := transaction.QueryRow(ctx, `SELECT next_sequence, latest_event_hash
FROM mesh_audit.audit_stream
WHERE id = 1
FOR UPDATE`).Scan(&sequence, &previousHash); err != nil {
		t.Fatalf("load transition fixture audit head: %v", err)
	}
	hashInput := append([]byte{}, previousHash...)
	hashInput = append(hashInput, transitionIntegrationMigrationID...)
	eventHash := sha256.Sum256(hashInput)
	var appended int64
	if err := transaction.QueryRow(ctx, `SELECT mesh_audit.append_authority_evidence(
    1::BIGINT,
    '01890f42-0000-7000-8000-000000000001'::UUID,
    '01890f43-0000-7000-8000-000000000001'::UUID,
    $1::BIGINT, $2::BYTEA, $3::BYTEA,
    'identity_provider'::TEXT, $4::UUID, 1::BIGINT, NULL::BIGINT,
    $5::UUID, 'identity.subject_transition.fixture_created'::TEXT,
    'system.bootstrap'::TEXT, NULL::UUID, NULL::BYTEA, NULL::BYTEA,
    '{}'::JSONB, 'identity.subject_transition.fixture_created'::TEXT, '{}'::JSONB
)`, sequence, previousHash, eventHash[:], transitionIntegrationSourceID,
		transitionIntegrationActorID).Scan(&appended); err != nil {
		t.Fatalf("append transition fixture audit evidence: %v", err)
	}
	if appended != sequence {
		t.Fatalf("transition fixture audit sequence = %d, want %d", appended, sequence)
	}
}

func loadTransitionIntegrationSnapshot(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) string {
	t.Helper()
	var snapshot string
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.jsonb_build_object(
    'source_provider', (SELECT pg_catalog.to_jsonb(provider) FROM mesh.identity_provider AS provider WHERE provider.public_id = $1::UUID),
    'source_generation', (SELECT pg_catalog.to_jsonb(generation) FROM mesh.identity_provider_generation AS generation WHERE generation.identity_provider_id = 9601),
    'source_client', (SELECT pg_catalog.to_jsonb(client) FROM mesh.identity_provider_client AS client WHERE client.identity_provider_id = 9601),
    'target_provider', (SELECT pg_catalog.to_jsonb(provider) FROM mesh.identity_provider AS provider WHERE provider.public_id = $2::UUID),
    'target_generation', (SELECT pg_catalog.to_jsonb(generation) FROM mesh.identity_provider_generation AS generation WHERE generation.identity_provider_id = 9602),
    'target_client', (SELECT pg_catalog.to_jsonb(client) FROM mesh.identity_provider_client AS client WHERE client.identity_provider_id = 9602),
    'principal', (SELECT pg_catalog.to_jsonb(principal) FROM mesh.principal AS principal WHERE principal.public_id = $3::UUID),
    'account', (SELECT pg_catalog.to_jsonb(account) FROM mesh.account AS account WHERE account.public_id = $4::UUID),
    'subject', (SELECT pg_catalog.to_jsonb(subject) FROM mesh.identity_subject AS subject WHERE subject.public_id = $5::UUID),
    'session', (SELECT pg_catalog.to_jsonb(session) FROM mesh.account_session AS session WHERE session.public_id = $6::UUID),
    'auth', (SELECT pg_catalog.to_jsonb(auth) FROM mesh.auth_transaction AS auth WHERE auth.public_id = $7::UUID),
    'authority_mutations', (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation),
    'audit_event_identities', (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event_identity),
    'outbox_events', (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event)
)::TEXT`,
		transitionIntegrationSourceID,
		transitionIntegrationTargetID,
		transitionIntegrationPrincipalID,
		transitionIntegrationAccountID,
		transitionIntegrationSubjectID,
		transitionIntegrationSessionID,
		transitionIntegrationAuthID,
	).Scan(&snapshot); err != nil {
		t.Fatalf("load transition fixture snapshot: %v", err)
	}
	return snapshot
}

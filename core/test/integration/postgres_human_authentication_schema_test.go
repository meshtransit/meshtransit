//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
)

const (
	integrationAuthTransactionPublicID = "01890f00-0000-7000-8000-000000000801"
	integrationAccountSessionPublicID  = "01890f00-0000-7000-8000-000000000811"
	integrationIdentityLinkPublicID    = "01890f00-0000-7000-8000-000000000821"
	integrationLogoutReplayPublicID    = "01890f00-0000-7000-8000-000000000831"
)

func assertHumanAuthenticationSessionAuthority(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	adminContenderConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()

	seedHumanAuthenticationAuthority(ctx, t, adminConnection)
	assertHumanAuthenticationRows(ctx, t, adminConnection)
	assertHumanAuthenticationConstraints(ctx, t, adminConnection)
	assertRuntimeAccountSessionResolutionV2(ctx, t, runtimePool)
	assertRuntimeAccountSessionResolution(ctx, t, adminConnection, runtimeConnection)
	assertConcurrentAccountSessionRevocation(
		ctx,
		t,
		adminConnection,
		adminContenderConnection,
	)
	assertHumanAuthenticationPrivilegeContract(ctx, t, adminConnection, runtimeConnection)
}

func assertRuntimeAccountSessionResolutionV2(
	ctx context.Context,
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()

	store, err := postgresadapter.NewAccountSessionStore(
		runtimePool,
		postgresadapter.AccountSessionOptions{
			StatementTimeout: 5 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewAccountSessionStore() error = %v", err)
	}
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("parse integration Deployment: %v", err)
	}
	keyID, err := accountsession.NewDigestKeyID("integration-v1")
	if err != nil {
		t.Fatalf("parse integration Account Session digest key: %v", err)
	}
	var digestBytes [32]byte
	for index := range digestBytes {
		digestBytes[index] = 0xaa
	}
	digest, err := accountsession.NewDigest(keyID, digestBytes)
	if err != nil {
		t.Fatalf("construct integration Account Session digest: %v", err)
	}
	session, found, err := store.Resolve(ctx, deploymentID, 1, digest)
	if err != nil {
		t.Fatalf("resolve deployment-bound Account Session: %v", err)
	}
	workspaceID, hasWorkspace := session.LoginWorkspaceID()
	if !found || !session.IsValid() ||
		session.ID().String() != integrationAccountSessionPublicID ||
		session.DeploymentID() != deploymentID ||
		session.PrincipalID().String() != "01890f00-0000-7000-8000-000000000011" ||
		session.IdentitySubjectID().String() != integrationIdentitySubjectPublicID ||
		!hasWorkspace ||
		workspaceID.String() != "01890f00-0000-7000-8000-000000000101" ||
		session.DeploymentRecoveryEpoch() != 1 {
		t.Fatalf("deployment-bound Account Session = %+v, want exact active authority", session)
	}

	otherDeploymentID, err := deployment.ParseID(
		"01890f00-0000-7000-8000-000000000002",
	)
	if err != nil {
		t.Fatalf("parse alternate integration Deployment: %v", err)
	}
	for name, candidate := range map[string]struct {
		deploymentID  deployment.ID
		recoveryEpoch int64
	}{
		"wrong deployment":     {deploymentID: otherDeploymentID, recoveryEpoch: 1},
		"wrong recovery epoch": {deploymentID: deploymentID, recoveryEpoch: 2},
	} {
		t.Run(name, func(t *testing.T) {
			resolved, resolvedFound, resolveErr := store.Resolve(
				ctx,
				candidate.deploymentID,
				candidate.recoveryEpoch,
				digest,
			)
			if resolveErr != nil || resolvedFound || resolved.IsValid() {
				t.Fatalf(
					"Resolve() = (%+v, %t, %v), want hidden mismatch",
					resolved,
					resolvedFound,
					resolveErr,
				)
			}
		})
	}
}

func seedHumanAuthenticationAuthority(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()

	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000000801",
		eventPublicID:          "01890f02-0000-7000-8000-000000000801",
		outboxPublicID:         "01890f03-0000-7000-8000-000000000801",
		streamID:               1,
		aggregateKind:          "account_session",
		aggregatePublicID:      integrationAccountSessionPublicID,
		aggregateVersion:       1,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "account_session.created",
		permission:             "system.bootstrap",
		outboxEventClass:       "account_session.created",
	}, func(transaction pgx.Tx) {
		statements := []struct {
			name  string
			query string
		}{
			{
				name: "authentication transaction",
				query: `INSERT INTO mesh.auth_transaction (
    id, public_id, deployment_id, workspace_id, identity_provider_id,
    identity_provider_client_id, principal_id, flow_kind, operation_kind,
    operation_semantic_hash, state_digest_algorithm, state_digest_key_id,
    state_digest, nonce_digest_algorithm, nonce_digest_key_id, nonce_digest,
    pkce_verifier_encryption_algorithm, pkce_verifier_encryption_key_id,
    pkce_verifier_ciphertext, redirect_id, return_route_id, provider_generation,
    deployment_recovery_epoch, account_session_generation, expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    801, '01890f00-0000-7000-8000-000000000801', 1, 101, 601, 621, 11,
    'browser_authorization_code', 'identity_link',
    pg_catalog.decode(pg_catalog.repeat('40', 32), 'hex'),
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('41', 32), 'hex'),
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('42', 32), 'hex'),
    'aead-aes-256-gcm-v1', 'integration-aead-v1',
    pg_catalog.decode(pg_catalog.repeat('43', 96), 'hex'),
    'console-callback', 'workspace-home', 1, 1, 1,
    pg_catalog.transaction_timestamp() + INTERVAL '10 minutes', 'pending'
)`,
			},
			{
				name: "account session",
				query: `INSERT INTO mesh.account_session (
    id, public_id, deployment_id, principal_id, identity_provider_id,
    identity_subject_id, identity_provider_client_id, login_workspace_id,
    token_digest_algorithm, token_digest_key_id, token_digest,
    provider_generation, provider_sid_digest_algorithm,
    provider_sid_digest_key_id, provider_sid_digest, authentication_time,
    acr, amr, principal_authority_generation, account_session_generation,
    deployment_recovery_epoch, issued_at, last_used_at, idle_expires_at,
    absolute_expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    811, '01890f00-0000-7000-8000-000000000811', 1, 11, 601, 711, 621, 101,
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('aa', 32), 'hex'), 1,
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('bb', 32), 'hex'),
    pg_catalog.transaction_timestamp() - INTERVAL '1 minute',
    'urn:meshtransit:assurance:mfa', ARRAY['pwd', 'mfa'], 1, 1, 1,
    pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp(),
    pg_catalog.transaction_timestamp() + INTERVAL '30 minutes',
    pg_catalog.transaction_timestamp() + INTERVAL '8 hours', 'active'
)`,
			},
			{
				name: "identity link request",
				query: `INSERT INTO mesh.identity_link_request (
    id, public_id, deployment_id, current_principal_id,
    candidate_identity_provider_id, candidate_subject_digest_algorithm,
    candidate_subject_digest_key_id, candidate_subject_digest,
    current_proof_account_session_id, candidate_proof_auth_transaction_id,
    proof_kind, operation_semantic_hash, expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    821, '01890f00-0000-7000-8000-000000000821', 1, 11, 601,
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('44', 32), 'hex'),
    811, 801, 'dual_authentication',
    pg_catalog.decode(pg_catalog.repeat('45', 32), 'hex'),
    pg_catalog.transaction_timestamp() + INTERVAL '10 minutes', 'pending'
)`,
			},
			{
				name: "OIDC logout replay",
				query: `INSERT INTO mesh.oidc_logout_replay (
    id, public_id, deployment_id, identity_provider_id,
    identity_provider_client_id, jti_digest_algorithm, jti_digest_key_id,
    jti_digest, sid_digest_algorithm, sid_digest_key_id, sid_digest,
    issued_at, expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    831, '01890f00-0000-7000-8000-000000000831', 1, 601, 621,
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('cc', 32), 'hex'),
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('bb', 32), 'hex'),
    pg_catalog.transaction_timestamp() - INTERVAL '1 minute',
    pg_catalog.transaction_timestamp() + INTERVAL '10 minutes', 'processing'
)`,
			},
		}
		for _, statement := range statements {
			if _, err := transaction.Exec(ctx, statement.query); err != nil {
				t.Fatalf("insert integration %s: %v", statement.name, err)
			}
		}
	})
}

func assertHumanAuthenticationRows(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()

	var transactionState, sessionState, linkState, logoutState string
	var mutationCount int64
	if err := connection.QueryRow(ctx, `SELECT
    auth_transaction.state,
    account_session.state,
    identity_link_request.state,
    logout_replay.state,
    (
        SELECT pg_catalog.count(*)
        FROM mesh_audit.authority_mutation AS mutation
        WHERE mutation.change_public_id = '01890f01-0000-7000-8000-000000000801'
    )
FROM mesh.auth_transaction AS auth_transaction
JOIN mesh.account_session AS account_session
  ON account_session.public_id = $2
JOIN mesh.identity_link_request AS identity_link_request
  ON identity_link_request.public_id = $3
JOIN mesh.oidc_logout_replay AS logout_replay
  ON logout_replay.public_id = $4
WHERE auth_transaction.public_id = $1`,
		integrationAuthTransactionPublicID,
		integrationAccountSessionPublicID,
		integrationIdentityLinkPublicID,
		integrationLogoutReplayPublicID,
	).Scan(
		&transactionState,
		&sessionState,
		&linkState,
		&logoutState,
		&mutationCount,
	); err != nil {
		t.Fatalf("query human authentication authority: %v", err)
	}
	if transactionState != "pending" || sessionState != "active" ||
		linkState != "pending" || logoutState != "processing" || mutationCount != 4 {
		t.Fatalf(
			"human authentication states transaction=%s session=%s link=%s logout=%s mutations=%d",
			transactionState,
			sessionState,
			linkState,
			logoutState,
			mutationCount,
		)
	}
}

func assertHumanAuthenticationConstraints(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()

	t.Run("state digest cannot replay", func(t *testing.T) {
		_, err := connection.Exec(ctx, `INSERT INTO mesh.auth_transaction (
    id, public_id, deployment_id, workspace_id, identity_provider_id,
    identity_provider_client_id, principal_id, flow_kind, operation_kind,
    operation_semantic_hash, state_digest_algorithm, state_digest_key_id,
    state_digest, nonce_digest_algorithm, nonce_digest_key_id, nonce_digest,
    pkce_verifier_encryption_algorithm, pkce_verifier_encryption_key_id,
    pkce_verifier_ciphertext, redirect_id, return_route_id, provider_generation,
    deployment_recovery_epoch, account_session_generation, expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    802, '01890f00-0000-7000-8000-000000000802', 1, 101, 601, 621, 11,
    'browser_authorization_code', 'identity_link',
    pg_catalog.decode(pg_catalog.repeat('46', 32), 'hex'),
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('41', 32), 'hex'),
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('47', 32), 'hex'),
    'aead-aes-256-gcm-v1', 'integration-aead-v1',
    pg_catalog.decode(pg_catalog.repeat('48', 96), 'hex'),
    'console-callback', 'workspace-home', 1, 1, 1,
    pg_catalog.transaction_timestamp() + INTERVAL '10 minutes', 'pending'
)`)
		assertPostgreSQLCode(t, err, "23505")
	})

	t.Run("transaction cannot skip consuming state", func(t *testing.T) {
		_, err := connection.Exec(ctx, `UPDATE mesh.auth_transaction
SET
    state = 'succeeded',
    consumed_at = pg_catalog.transaction_timestamp(),
    consumed_result_kind = 'identity_proof',
    consumed_result_public_id = '01890f00-0000-7000-8000-000000000899',
    pkce_verifier_encryption_algorithm = NULL,
    pkce_verifier_encryption_key_id = NULL,
    pkce_verifier_ciphertext = NULL,
    version = 2,
    updated_at = pg_catalog.transaction_timestamp()
WHERE public_id = $1`, integrationAuthTransactionPublicID)
		assertPostgreSQLCode(t, err, "23514")
	})

	t.Run("session handle cannot replay", func(t *testing.T) {
		_, err := connection.Exec(ctx, `INSERT INTO mesh.account_session (
    id, public_id, deployment_id, principal_id, identity_provider_id,
    identity_subject_id, identity_provider_client_id, login_workspace_id,
    token_digest_algorithm, token_digest_key_id, token_digest,
    provider_generation, authentication_time, amr,
    principal_authority_generation, account_session_generation,
    deployment_recovery_epoch, issued_at, last_used_at, idle_expires_at,
    absolute_expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    812, '01890f00-0000-7000-8000-000000000812', 1, 11, 601, 711, 621, 101,
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('aa', 32), 'hex'), 1,
    pg_catalog.transaction_timestamp() - INTERVAL '1 minute', ARRAY[]::TEXT[],
    1, 1, 1, pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp(),
    pg_catalog.transaction_timestamp() + INTERVAL '30 minutes',
    pg_catalog.transaction_timestamp() + INTERVAL '8 hours', 'active'
)`)
		assertPostgreSQLCode(t, err, "23505")
	})

	t.Run("identity link requires dual proof", func(t *testing.T) {
		_, err := connection.Exec(ctx, `INSERT INTO mesh.identity_link_request (
    id, public_id, deployment_id, current_principal_id,
    candidate_identity_provider_id, candidate_subject_digest_algorithm,
    candidate_subject_digest_key_id, candidate_subject_digest,
    candidate_proof_auth_transaction_id, proof_kind,
    operation_semantic_hash, expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    822, '01890f00-0000-7000-8000-000000000822', 1, 11, 601,
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('49', 32), 'hex'),
    801, 'dual_authentication',
    pg_catalog.decode(pg_catalog.repeat('50', 32), 'hex'),
    pg_catalog.transaction_timestamp() + INTERVAL '10 minutes', 'pending'
)`)
		assertPostgreSQLConstraint(t, err, "identity_link_request_proof_check")
	})

	t.Run("logout jti cannot replay", func(t *testing.T) {
		_, err := connection.Exec(ctx, `INSERT INTO mesh.oidc_logout_replay (
    id, public_id, deployment_id, identity_provider_id,
    identity_provider_client_id, jti_digest_algorithm, jti_digest_key_id,
    jti_digest, sid_digest_algorithm, sid_digest_key_id, sid_digest,
    issued_at, expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    832, '01890f00-0000-7000-8000-000000000832', 1, 601, 621,
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('cc', 32), 'hex'),
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('bb', 32), 'hex'),
    pg_catalog.transaction_timestamp() - INTERVAL '1 minute',
    pg_catalog.transaction_timestamp() + INTERVAL '10 minutes', 'processing'
)`)
		assertPostgreSQLCode(t, err, "23505")
	})

	t.Run("logout requires sid or subject", func(t *testing.T) {
		_, err := connection.Exec(ctx, `INSERT INTO mesh.oidc_logout_replay (
    id, public_id, deployment_id, identity_provider_id,
    identity_provider_client_id, jti_digest_algorithm, jti_digest_key_id,
    jti_digest, issued_at, expires_at, state
) OVERRIDING SYSTEM VALUE VALUES (
    833, '01890f00-0000-7000-8000-000000000833', 1, 601, 621,
    'hmac-sha256-v1', 'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('cd', 32), 'hex'),
    pg_catalog.transaction_timestamp() - INTERVAL '1 minute',
    pg_catalog.transaction_timestamp() + INTERVAL '10 minutes', 'processing'
)`)
		assertPostgreSQLConstraint(t, err, "oidc_logout_replay_target_check")
	})

	t.Run("session history cannot be deleted", func(t *testing.T) {
		_, err := connection.Exec(
			ctx,
			"DELETE FROM mesh.account_session WHERE public_id = $1",
			integrationAccountSessionPublicID,
		)
		assertPostgreSQLCode(t, err, "55000")
	})

	var forbiddenRawColumns int64
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM pg_catalog.pg_attribute AS attribute
JOIN pg_catalog.pg_class AS relation ON relation.oid = attribute.attrelid
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = 'mesh'
  AND relation.relname IN (
      'auth_transaction',
      'account_session',
      'identity_link_request',
      'oidc_logout_replay'
  )
  AND attribute.attnum > 0
  AND NOT attribute.attisdropped
  AND attribute.attname IN (
      'state_token', 'nonce', 'pkce_verifier', 'session_token',
      'provider_token', 'refresh_token', 'raw_subject', 'subject', 'email'
  )`).Scan(&forbiddenRawColumns); err != nil {
		t.Fatalf("query raw authentication columns: %v", err)
	}
	if forbiddenRawColumns != 0 {
		t.Fatalf("raw authentication columns = %d, want 0", forbiddenRawColumns)
	}
}

func assertRuntimeAccountSessionResolution(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
) {
	t.Helper()

	var sessionState, deploymentState, deploymentRecoveryState, principalState string
	var accountRecoveryState, subjectState, providerState, providerRecoveryState string
	var clientState, workspaceState string
	var idleCurrent, absoluteCurrent bool
	var deploymentEpoch, sessionDeploymentEpoch int64
	var principalGeneration, sessionPrincipalGeneration int64
	var accountGeneration, sessionAccountGeneration int64
	var providerGeneration, sessionProviderGeneration int64
	if err := adminConnection.QueryRow(ctx, `SELECT
    session.state,
    session.idle_expires_at > pg_catalog.transaction_timestamp(),
    session.absolute_expires_at > pg_catalog.transaction_timestamp(),
    deployment.state,
    deployment.recovery_state,
    deployment.recovery_epoch,
    session.deployment_recovery_epoch,
    principal.state,
    principal.authority_generation,
    session.principal_authority_generation,
    account.recovery_state,
    account.session_generation,
    session.account_session_generation,
    subject.state,
    provider.state,
    provider.recovery_state,
    provider.current_generation,
    session.provider_generation,
    client.state,
    workspace.state
FROM mesh.account_session AS session
JOIN mesh.deployment AS deployment ON deployment.id = session.deployment_id
JOIN mesh.principal AS principal
  ON principal.deployment_id = session.deployment_id
 AND principal.id = session.principal_id
JOIN mesh.account AS account
  ON account.deployment_id = session.deployment_id
 AND account.principal_id = session.principal_id
JOIN mesh.identity_subject AS subject
  ON subject.deployment_id = session.deployment_id
 AND subject.identity_provider_id = session.identity_provider_id
 AND subject.principal_id = session.principal_id
 AND subject.id = session.identity_subject_id
JOIN mesh.identity_provider AS provider
  ON provider.deployment_id = session.deployment_id
 AND provider.id = session.identity_provider_id
JOIN mesh.identity_provider_client AS client
  ON client.deployment_id = session.deployment_id
 AND client.identity_provider_id = session.identity_provider_id
 AND client.id = session.identity_provider_client_id
JOIN mesh.workspace AS workspace
  ON workspace.deployment_id = session.deployment_id
 AND workspace.id = session.login_workspace_id
WHERE session.public_id = $1`, integrationAccountSessionPublicID).Scan(
		&sessionState,
		&idleCurrent,
		&absoluteCurrent,
		&deploymentState,
		&deploymentRecoveryState,
		&deploymentEpoch,
		&sessionDeploymentEpoch,
		&principalState,
		&principalGeneration,
		&sessionPrincipalGeneration,
		&accountRecoveryState,
		&accountGeneration,
		&sessionAccountGeneration,
		&subjectState,
		&providerState,
		&providerRecoveryState,
		&providerGeneration,
		&sessionProviderGeneration,
		&clientState,
		&workspaceState,
	); err != nil {
		t.Fatalf("query account session authority inputs: %v", err)
	}
	if sessionState != "active" || !idleCurrent || !absoluteCurrent ||
		deploymentState != "active" || deploymentRecoveryState != "verified" ||
		deploymentEpoch != sessionDeploymentEpoch || principalState != "active" ||
		principalGeneration != sessionPrincipalGeneration ||
		accountRecoveryState != "verified" || accountGeneration != sessionAccountGeneration ||
		subjectState != "active" || providerState != "active" ||
		providerRecoveryState != "verified" || providerGeneration != sessionProviderGeneration ||
		clientState != "active" || workspaceState != "active" {
		t.Fatalf(
			"invalid session authority inputs state=%s idle=%t absolute=%t deployment=%s/%s/%d:%d principal=%s/%d:%d account=%s/%d:%d subject=%s provider=%s/%s/%d:%d client=%s workspace=%s",
			sessionState,
			idleCurrent,
			absoluteCurrent,
			deploymentState,
			deploymentRecoveryState,
			deploymentEpoch,
			sessionDeploymentEpoch,
			principalState,
			principalGeneration,
			sessionPrincipalGeneration,
			accountRecoveryState,
			accountGeneration,
			sessionAccountGeneration,
			subjectState,
			providerState,
			providerRecoveryState,
			providerGeneration,
			sessionProviderGeneration,
			clientState,
			workspaceState,
		)
	}

	var sessionPublicID, principalPublicID, subjectPublicID, workspacePublicID string
	if err := runtimeConnection.QueryRow(ctx, `SELECT
    session_public_id,
    principal_public_id,
    identity_subject_public_id,
    login_workspace_public_id
FROM mesh_ops.resolve_account_session(
    'hmac-sha256-v1',
    'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('aa', 32), 'hex')
)`).Scan(
		&sessionPublicID,
		&principalPublicID,
		&subjectPublicID,
		&workspacePublicID,
	); err != nil {
		t.Fatalf("resolve valid account session: %v", err)
	}
	if sessionPublicID != integrationAccountSessionPublicID ||
		principalPublicID != "01890f00-0000-7000-8000-000000000011" ||
		subjectPublicID != integrationIdentitySubjectPublicID ||
		workspacePublicID != "01890f00-0000-7000-8000-000000000101" {
		t.Fatalf(
			"resolved session=%s principal=%s subject=%s workspace=%s",
			sessionPublicID,
			principalPublicID,
			subjectPublicID,
			workspacePublicID,
		)
	}

	runtimeTransaction, err := runtimeConnection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin session resolver scope restoration transaction: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, runtimeTransaction)
	if _, err := runtimeTransaction.Exec(
		ctx,
		"SELECT pg_catalog.set_config('mesh.workspace_id', $1, TRUE)",
		"102",
	); err != nil {
		t.Fatalf("set prior session resolver workspace scope: %v", err)
	}
	var scopedResolutionCount int64
	if err := runtimeTransaction.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.resolve_account_session(
    'hmac-sha256-v1',
    'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('aa', 32), 'hex')
)`).Scan(&scopedResolutionCount); err != nil {
		t.Fatalf("resolve account session with prior workspace scope: %v", err)
	}
	var restoredWorkspaceScope string
	if err := runtimeTransaction.QueryRow(
		ctx,
		"SELECT pg_catalog.current_setting('mesh.workspace_id', TRUE)",
	).Scan(&restoredWorkspaceScope); err != nil {
		t.Fatalf("query restored session resolver workspace scope: %v", err)
	}
	if scopedResolutionCount != 1 || restoredWorkspaceScope != "102" {
		t.Fatalf(
			"scoped session resolution count=%d restored-workspace=%q",
			scopedResolutionCount,
			restoredWorkspaceScope,
		)
	}
	if err := runtimeTransaction.Rollback(ctx); err != nil {
		t.Fatalf("rollback session resolver scope restoration transaction: %v", err)
	}

	_, err = runtimeConnection.Exec(ctx, `SELECT *
FROM mesh_ops.resolve_account_session(
    'hmac-sha256-v1',
    'integration-v1',
    pg_catalog.decode('aa', 'hex')
)`)
	assertPostgreSQLCode(t, err, "22023")

	commitAuditedAuthorityFixture(ctx, t, adminConnection, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000000802",
		eventPublicID:          "01890f02-0000-7000-8000-000000000802",
		outboxPublicID:         "01890f03-0000-7000-8000-000000000802",
		streamID:               1,
		aggregateKind:          "account",
		aggregatePublicID:      integrationAccountPublicID,
		aggregateVersion:       2,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "account.session_generation_advanced",
		permission:             "session.revoke",
		outboxEventClass:       "account.session_generation_advanced",
	}, func(transaction pgx.Tx) {
		if _, err := transaction.Exec(ctx, `UPDATE mesh.account
SET
    session_generation = 2,
    version = 2,
    updated_at = pg_catalog.transaction_timestamp()
WHERE public_id = $1`, integrationAccountPublicID); err != nil {
			t.Fatalf("advance integration account session generation: %v", err)
		}
	})

	var resolvedCount int64
	if err := runtimeConnection.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.resolve_account_session(
    'hmac-sha256-v1',
    'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('aa', 32), 'hex')
)`).Scan(&resolvedCount); err != nil {
		t.Fatalf("resolve generation-stale account session: %v", err)
	}
	if resolvedCount != 0 {
		t.Fatalf("generation-stale resolved sessions = %d, want 0", resolvedCount)
	}
}

type concurrentRevocationResult struct {
	revokedCount int64
	err          error
}

func assertConcurrentAccountSessionRevocation(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	contenderConnection *pgx.Conn,
) {
	t.Helper()

	var contenderPID int64
	if err := contenderConnection.QueryRow(ctx, "SELECT pg_catalog.pg_backend_pid()").Scan(
		&contenderPID,
	); err != nil {
		t.Fatalf("query revocation contender PID: %v", err)
	}

	winner, err := adminConnection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin winning revocation transaction: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, winner)
	setIntegrationChange(ctx, t, winner, "01890f01-0000-7000-8000-000000000803")

	var revokedPublicID string
	var revokedVersion int64
	if err := winner.QueryRow(ctx, `SELECT session_public_id, session_version
FROM mesh_ops.revoke_account_session(
    'hmac-sha256-v1',
    'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('aa', 32), 'hex'),
    'local_logout'
)`).Scan(&revokedPublicID, &revokedVersion); err != nil {
		t.Fatalf("revoke account session in winning transaction: %v", err)
	}
	if revokedPublicID != integrationAccountSessionPublicID || revokedVersion != 2 {
		t.Fatalf(
			"winning revocation session=%s version=%d",
			revokedPublicID,
			revokedVersion,
		)
	}

	started := make(chan struct{})
	result := make(chan concurrentRevocationResult, 1)
	go func() {
		contender, beginErr := contenderConnection.Begin(ctx)
		if beginErr != nil {
			close(started)
			result <- concurrentRevocationResult{err: beginErr}
			return
		}
		defer func() {
			cleanupCtx, cancel := context.WithTimeout(
				context.WithoutCancel(ctx),
				integrationCleanupTimeout,
			)
			defer cancel()
			_ = contender.Rollback(cleanupCtx)
		}()
		_, setErr := contender.Exec(
			ctx,
			"SELECT pg_catalog.set_config('mesh.change_public_id', $1, TRUE)",
			"01890f01-0000-7000-8000-000000000804",
		)
		close(started)
		if setErr != nil {
			result <- concurrentRevocationResult{err: setErr}
			return
		}
		var revokedCount int64
		queryErr := contender.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.revoke_account_session(
    'hmac-sha256-v1',
    'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('aa', 32), 'hex'),
    'local_logout'
)`).Scan(&revokedCount)
		if queryErr == nil {
			queryErr = contender.Commit(ctx)
		}
		result <- concurrentRevocationResult{
			revokedCount: revokedCount,
			err:          queryErr,
		}
	}()
	<-started

	waitDeadline := time.Now().Add(5 * time.Second)
	for {
		var waitingOnLock bool
		if err := winner.QueryRow(ctx, `SELECT COALESCE(wait_event_type = 'Lock', FALSE)
FROM pg_catalog.pg_stat_activity
WHERE pid = $1`, contenderPID).Scan(&waitingOnLock); err != nil {
			t.Fatalf("query revocation contender wait state: %v", err)
		}
		if waitingOnLock {
			break
		}
		if time.Now().After(waitDeadline) {
			t.Fatal("concurrent revocation did not wait on the session row lock")
		}
		time.Sleep(10 * time.Millisecond)
	}

	appendIntegrationAuthorityEvidence(ctx, t, winner, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000000803",
		eventPublicID:          "01890f02-0000-7000-8000-000000000803",
		outboxPublicID:         "01890f03-0000-7000-8000-000000000803",
		streamID:               1,
		aggregateKind:          "account_session",
		aggregatePublicID:      integrationAccountSessionPublicID,
		aggregateVersion:       2,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "account_session.revoked",
		permission:             "session.revoke",
		outboxEventClass:       "account_session.revoked",
	})
	if err := winner.Commit(ctx); err != nil {
		t.Fatalf("commit winning revocation transaction: %v", err)
	}

	select {
	case contenderResult := <-result:
		if contenderResult.err != nil {
			t.Fatalf("concurrent revocation contender: %v", contenderResult.err)
		}
		if contenderResult.revokedCount != 0 {
			t.Fatalf(
				"concurrent revocation contender count = %d, want 0",
				contenderResult.revokedCount,
			)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent revocation contender did not finish")
	}

	var state, endReason string
	var version int64
	if err := adminConnection.QueryRow(ctx, `SELECT state, end_reason, version
FROM mesh.account_session
WHERE public_id = $1`, integrationAccountSessionPublicID).Scan(
		&state,
		&endReason,
		&version,
	); err != nil {
		t.Fatalf("query revoked account session: %v", err)
	}
	if state != "revoked" || endReason != "local_logout" || version != 2 {
		t.Fatalf(
			"revoked account session state=%s reason=%s version=%d",
			state,
			endReason,
			version,
		)
	}
}

func assertHumanAuthenticationPrivilegeContract(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
) {
	t.Helper()

	var runtimeCanResolveV2, workerCanResolveV2 bool
	if err := adminConnection.QueryRow(ctx, `SELECT
    pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.resolve_account_session_v2(uuid,bigint,text,text,bytea)',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_worker',
        'mesh_ops.resolve_account_session_v2(uuid,bigint,text,text,bytea)',
        'EXECUTE'
    )`).Scan(&runtimeCanResolveV2, &workerCanResolveV2); err != nil {
		t.Fatalf("query Account Session v2 privilege contract: %v", err)
	}
	if !runtimeCanResolveV2 || workerCanResolveV2 {
		t.Fatalf(
			"Account Session v2 privileges runtime=%t worker=%t, want true/false",
			runtimeCanResolveV2,
			workerCanResolveV2,
		)
	}

	var runtimeHasTableAccess, workerHasTableAccess, observerHasTableAccess bool
	var runtimeCanResolve, runtimeCanRevoke, workerCanResolve, workerCanRevoke bool
	if err := adminConnection.QueryRow(ctx, `SELECT
    COALESCE(pg_catalog.bool_or(
        pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'SELECT')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'INSERT')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'UPDATE')
        OR pg_catalog.has_table_privilege('mesh_runtime', relation.oid, 'DELETE')
    ), FALSE),
    COALESCE(pg_catalog.bool_or(
        pg_catalog.has_table_privilege('mesh_worker', relation.oid, 'SELECT')
        OR pg_catalog.has_table_privilege('mesh_worker', relation.oid, 'INSERT')
        OR pg_catalog.has_table_privilege('mesh_worker', relation.oid, 'UPDATE')
        OR pg_catalog.has_table_privilege('mesh_worker', relation.oid, 'DELETE')
    ), FALSE),
    COALESCE(pg_catalog.bool_or(
        pg_catalog.has_table_privilege('mesh_observer', relation.oid, 'SELECT')
        OR pg_catalog.has_table_privilege('mesh_observer', relation.oid, 'INSERT')
        OR pg_catalog.has_table_privilege('mesh_observer', relation.oid, 'UPDATE')
        OR pg_catalog.has_table_privilege('mesh_observer', relation.oid, 'DELETE')
    ), FALSE),
    pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.resolve_account_session(text,text,bytea)',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_runtime',
        'mesh_ops.revoke_account_session(text,text,bytea,text)',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_worker',
        'mesh_ops.resolve_account_session(text,text,bytea)',
        'EXECUTE'
    ),
    pg_catalog.has_function_privilege(
        'mesh_worker',
        'mesh_ops.revoke_account_session(text,text,bytea,text)',
        'EXECUTE'
    )
FROM pg_catalog.pg_class AS relation
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
WHERE namespace.nspname = 'mesh'
  AND relation.relname IN (
      'auth_transaction',
      'account_session',
      'identity_link_request',
      'oidc_logout_replay'
  )`).Scan(
		&runtimeHasTableAccess,
		&workerHasTableAccess,
		&observerHasTableAccess,
		&runtimeCanResolve,
		&runtimeCanRevoke,
		&workerCanResolve,
		&workerCanRevoke,
	); err != nil {
		t.Fatalf("query human authentication privilege contract: %v", err)
	}
	if runtimeHasTableAccess || workerHasTableAccess || observerHasTableAccess ||
		!runtimeCanResolve || !runtimeCanRevoke || workerCanResolve || workerCanRevoke {
		t.Fatalf(
			"human authentication privileges runtime-table=%t worker-table=%t observer-table=%t runtime-resolve=%t runtime-revoke=%t worker-resolve=%t worker-revoke=%t",
			runtimeHasTableAccess,
			workerHasTableAccess,
			observerHasTableAccess,
			runtimeCanResolve,
			runtimeCanRevoke,
			workerCanResolve,
			workerCanRevoke,
		)
	}

	_, err := runtimeConnection.Exec(ctx, "SELECT public_id FROM mesh.account_session")
	assertPostgreSQLCode(t, err, "42501")

	_, err = runtimeConnection.Exec(ctx, `SELECT *
FROM mesh_ops.revoke_account_session(
    'hmac-sha256-v1',
    'integration-v1',
    pg_catalog.decode(pg_catalog.repeat('aa', 32), 'hex'),
    'unsupported_reason'
)`)
	assertPostgreSQLCode(t, err, "22023")
}

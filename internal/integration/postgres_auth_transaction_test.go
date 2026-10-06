//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const integrationCreatedAuthTransactionPublicID = "01890f00-0000-7000-8000-000000000951"

type integrationAuthRouteParams struct {
	providerGeneration int64
	recoveryEpoch      int64
}

func assertPostgreSQLAuthTransaction(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	adminContenderConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()

	store, err := postgresadapter.NewAuthTransactionStore(
		runtimePool,
		postgresadapter.AuthTransactionOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewAuthTransactionStore() error = %v", err)
	}
	pending := integrationAuthTransactionPending(
		t,
		integrationAuthRouteParams{
			providerGeneration: 1,
			recoveryEpoch:      1,
		},
		[4]string{
			integrationCreatedAuthTransactionPublicID,
			"01890f01-0000-7000-8000-000000000951",
			"01890f02-0000-7000-8000-000000000951",
			"01890f03-0000-7000-8000-000000000951",
		},
	)
	assertIntegrationAuthRoute(ctx, t, adminConnection, pending.Route())
	transaction, err := store.Begin(ctx, pending.Route())
	if err != nil {
		t.Fatalf("begin OIDC auth transaction: %v", err)
	}
	created, err := transaction.Create(ctx, pending)
	if err != nil {
		rollbackAuthTransactionIntegration(ctx, t, transaction)
		t.Fatalf("create OIDC auth transaction: %v", err)
	}
	assertOIDCAuthRouteLifecycleLock(ctx, t, adminContenderConnection)
	if err := transaction.Commit(ctx); err != nil {
		t.Fatalf("commit OIDC auth transaction: %v", err)
	}
	if !created.IsValid() || created.TransactionID() != pending.TransactionID() ||
		!created.CreatedAt().Equal(pending.CreatedAt()) ||
		!created.ExpiresAt().Equal(pending.ExpiresAt()) {
		t.Fatalf("created OIDC auth transaction = %+v, want exact durable evidence", created)
	}

	var state, action, eventClass string
	var stateDigestBytes, nonceDigestBytes, ciphertextBytes, bindingHashBytes int
	var actorAbsent, networkRevisionAbsent, workspaceAbsent bool
	var mutationCount int64
	if err := adminConnection.QueryRow(ctx, `SELECT
    auth.state,
    auth.workspace_id IS NULL,
    pg_catalog.octet_length(auth.state_digest),
    pg_catalog.octet_length(auth.nonce_digest),
    pg_catalog.octet_length(auth.pkce_verifier_ciphertext),
    pg_catalog.octet_length(auth.binding_semantic_hash),
    audit.action,
    audit.actor_principal_public_id IS NULL
      AND NOT (audit.payload ? 'workspace_public_id')
      AND NOT (outbox.payload ? 'workspace_public_id'),
    outbox.event_class,
    outbox.network_revision IS NULL,
    (
        SELECT pg_catalog.count(*)
        FROM mesh_audit.authority_mutation AS mutation
        WHERE mutation.change_public_id = $2::UUID
    )
FROM mesh.auth_transaction AS auth
JOIN mesh_audit.audit_event AS audit
  ON audit.target_kind = 'auth_transaction'
 AND audit.target_public_id = auth.public_id
JOIN mesh_ops.outbox_event AS outbox
  ON outbox.aggregate_kind = 'auth_transaction'
 AND outbox.aggregate_public_id = auth.public_id
WHERE auth.public_id = $1::UUID`,
		integrationCreatedAuthTransactionPublicID,
		pending.MutationIDs().ChangeID().String(),
	).Scan(
		&state,
		&workspaceAbsent,
		&stateDigestBytes,
		&nonceDigestBytes,
		&ciphertextBytes,
		&bindingHashBytes,
		&action,
		&actorAbsent,
		&eventClass,
		&networkRevisionAbsent,
		&mutationCount,
	); err != nil {
		t.Fatalf("query persisted OIDC auth transaction evidence: %v", err)
	}
	if !workspaceAbsent {
		t.Fatal("Workspace-less browser login persisted a Workspace before Account selection")
	}
	if state != "pending" || stateDigestBytes != 32 || nonceDigestBytes != 32 ||
		ciphertextBytes < 29 || bindingHashBytes != 32 ||
		action != "auth_transaction.created" || !actorAbsent ||
		eventClass != "identity.auth_transaction.created" || !networkRevisionAbsent ||
		mutationCount != 1 {
		t.Fatalf(
			"OIDC persistence state=%s state-bytes=%d nonce-bytes=%d cipher-bytes=%d binding-bytes=%d action=%s actor-absent=%t class=%s revision-absent=%t mutations=%d",
			state,
			stateDigestBytes,
			nonceDigestBytes,
			ciphertextBytes,
			bindingHashBytes,
			action,
			actorAbsent,
			eventClass,
			networkRevisionAbsent,
			mutationCount,
		)
	}

	replayed, found, err := store.ResolveCommitted(ctx, pending)
	if err != nil || !found || replayed.TransactionID() != pending.TransactionID() ||
		!replayed.CreatedAt().Equal(pending.CreatedAt()) ||
		!replayed.ExpiresAt().Equal(pending.ExpiresAt()) {
		t.Fatalf("ResolveCommitted() = (%+v, %t, %v), want exact creation", replayed, found, err)
	}

	for _, candidate := range []struct {
		name   string
		suffix string
		route  integrationAuthRouteParams
	}{
		{
			name:   "stale provider generation",
			suffix: "952",
			route: integrationAuthRouteParams{
				providerGeneration: 2,
				recoveryEpoch:      1,
			},
		},
		{
			name:   "stale recovery epoch",
			suffix: "953",
			route: integrationAuthRouteParams{
				providerGeneration: 1,
				recoveryEpoch:      2,
			},
		},
	} {
		t.Run(candidate.name, func(t *testing.T) {
			stalePending := integrationAuthTransactionPending(
				t,
				candidate.route,
				[4]string{
					"01890f00-0000-7000-8000-000000000" + candidate.suffix,
					"01890f01-0000-7000-8000-000000000" + candidate.suffix,
					"01890f02-0000-7000-8000-000000000" + candidate.suffix,
					"01890f03-0000-7000-8000-000000000" + candidate.suffix,
				},
			)
			staleTransaction, err := store.Begin(ctx, stalePending.Route())
			if err != nil {
				t.Fatalf("begin unavailable OIDC auth transaction: %v", err)
			}
			if _, err := staleTransaction.Create(ctx, stalePending); !errors.Is(err, postgresadapter.ErrAuthTransactionRouteUnavailable) {
				rollbackAuthTransactionIntegration(ctx, t, staleTransaction)
				t.Fatalf("create unavailable OIDC auth transaction error = %v, want route unavailable", err)
			}
			rollbackAuthTransactionIntegration(ctx, t, staleTransaction)
		})
	}
	assertPostgreSQLAuthStart(ctx, t, adminConnection, store)
}

func assertOIDCAuthRouteLifecycleLock(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()
	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin OIDC lifecycle lock contender: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, transaction)
	if _, err := transaction.Exec(ctx, "SELECT pg_catalog.set_config('lock_timeout', '100ms', TRUE)"); err != nil {
		t.Fatalf("configure OIDC lifecycle lock contender: %v", err)
	}
	setIntegrationChange(ctx, t, transaction, "01890f01-0000-7000-8000-000000000955")
	_, err = transaction.Exec(ctx, `UPDATE mesh.identity_provider
SET state = 'suspended', version = version + 1, updated_at = pg_catalog.transaction_timestamp()
WHERE public_id = $1::UUID`, integrationIdentityProviderPublicID)
	assertPostgreSQLCode(t, err, "55P03")
}

func assertIntegrationAuthRoute(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	route oidcauth.Route,
) {
	t.Helper()
	var deploymentOK, providerOK, generationOK, clientOK, bindingOK bool
	if err := connection.QueryRow(ctx, `SELECT
    EXISTS (
        SELECT 1 FROM mesh.deployment AS deployment
        WHERE deployment.installation_public_id = $1::UUID
          AND deployment.state = 'active'
          AND deployment.recovery_state = 'verified'
          AND deployment.deleted_at IS NULL
          AND deployment.recovery_epoch = $5::BIGINT
    ),
    EXISTS (
        SELECT 1 FROM mesh.identity_provider AS provider
        JOIN mesh.deployment AS deployment ON deployment.id = provider.deployment_id
        WHERE deployment.installation_public_id = $1::UUID
          AND provider.public_id = $2::UUID
          AND provider.state = 'active'
          AND provider.recovery_state = 'verified'
          AND provider.deleted_at IS NULL
          AND provider.current_generation = $4::BIGINT
          AND provider.issuer = $6::TEXT
          AND provider.discovery_uri = $7::TEXT
          AND provider.authorization_endpoint = $8::TEXT
          AND provider.token_endpoint = $9::TEXT
          AND provider.jwks_uri = $10::TEXT
    ),
    EXISTS (
        SELECT 1 FROM mesh.identity_provider_generation AS generation
        JOIN mesh.identity_provider AS provider ON provider.id = generation.identity_provider_id
        WHERE provider.public_id = $2::UUID
          AND generation.generation = $4::BIGINT
          AND generation.state = 'current'
          AND generation.valid_from <= pg_catalog.transaction_timestamp()
          AND generation.valid_until IS NULL
    ),
    EXISTS (
        SELECT 1 FROM mesh.identity_provider_client AS client
        JOIN mesh.identity_provider AS provider ON provider.id = client.identity_provider_id
        WHERE provider.public_id = $2::UUID
          AND client.public_id = $3::UUID
          AND client.state = 'active'
          AND client.deleted_at IS NULL
          AND client.client_kind = 'confidential'
          AND client.client_id = $11::TEXT
          AND client.client_auth_method = $12::TEXT
          AND client.pkce_s256_required
          AND 'authorization_code' = ANY (client.allowed_flows)
          AND client.allowed_scopes = $13::TEXT[]
          AND client.allowed_algorithms = $14::TEXT[]
          AND $15::TEXT = ANY (client.redirect_uris)
    ),
    EXISTS (
        SELECT 1 FROM mesh.workspace_identity_provider AS binding
        JOIN mesh.workspace AS workspace ON workspace.id = binding.workspace_id
        JOIN mesh.identity_provider AS provider ON provider.id = binding.identity_provider_id
        JOIN mesh.identity_provider_client AS client
          ON client.id = binding.identity_provider_client_id
        WHERE workspace.state = 'active'
          AND workspace.deleted_at IS NULL
          AND provider.public_id = $2::UUID
          AND client.public_id = $3::UUID
          AND binding.state = 'active'
          AND binding.deleted_at IS NULL
          AND binding.organization_digest_algorithm IS NULL
          AND binding.organization_digest_key_id IS NULL
          AND binding.organization_digest IS NULL
    )`,
		route.DeploymentID().String(),
		route.ProviderID().String(),
		route.ClientID().String(),
		route.ProviderGeneration(),
		route.RecoveryEpoch(),
		route.Issuer(),
		route.DiscoveryURI(),
		route.AuthorizationEndpoint(),
		route.TokenEndpoint(),
		route.JWKSURI(),
		route.OIDCClientID(),
		route.ClientAuthMethod(),
		route.Scopes(),
		route.AllowedAlgorithms(),
		route.RedirectURI(),
	).Scan(
		&deploymentOK,
		&providerOK,
		&generationOK,
		&clientOK,
		&bindingOK,
	); err != nil {
		t.Fatalf("query integration OIDC route preconditions: %v", err)
	}
	if !deploymentOK || !providerOK || !generationOK || !clientOK || !bindingOK {
		t.Fatalf(
			"integration OIDC route deployment=%t provider=%t generation=%t client=%t binding=%t",
			deploymentOK,
			providerOK,
			generationOK,
			clientOK,
			bindingOK,
		)
	}
}

func integrationAuthTransactionPending(
	t *testing.T,
	routeParams integrationAuthRouteParams,
	ids [4]string,
) oidcauth.Pending {
	t.Helper()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("parse integration Deployment: %v", err)
	}
	providerID, err := oidcauth.ParseProviderID(integrationIdentityProviderPublicID)
	if err != nil {
		t.Fatalf("parse integration provider: %v", err)
	}
	clientID, err := oidcauth.ParseClientID("01890f00-0000-7000-8000-000000000621")
	if err != nil {
		t.Fatalf("parse integration provider client: %v", err)
	}
	// #nosec G101 -- synthetic OIDC metadata contains only an auth-method identifier, no credentials.
	route, err := oidcauth.NewRoute(oidcauth.RouteParams{
		DeploymentID:          deploymentID,
		ProviderID:            providerID,
		ClientID:              clientID,
		ProviderGeneration:    routeParams.providerGeneration,
		RecoveryEpoch:         routeParams.recoveryEpoch,
		Issuer:                "https://idp.example.test/realms/main",
		DiscoveryURI:          "https://idp.example.test/realms/main/.well-known/openid-configuration",
		AuthorizationEndpoint: "https://idp.example.test/realms/main/protocol/openid-connect/auth",
		TokenEndpoint:         "https://idp.example.test/realms/main/protocol/openid-connect/token",
		JWKSURI:               "https://idp.example.test/realms/main/protocol/openid-connect/certs",
		OIDCClientID:          "meshtransit-console",
		ClientKind:            "confidential",
		ClientAuthMethod:      "client_secret_basic",
		Scopes:                []string{"openid", "profile"},
		AllowedAlgorithms:     []string{"RS256"},
		RedirectID:            "console-callback",
		RedirectURI:           "https://console.example.test/auth/callback",
		ReturnRouteID:         "workspace-home",
	})
	if err != nil {
		t.Fatalf("construct integration OIDC route: %v", err)
	}
	metadata, err := oidcauth.NewMetadata(oidcauth.MetadataParams{
		Issuer:                   route.Issuer(),
		AuthorizationEndpoint:    route.AuthorizationEndpoint(),
		TokenEndpoint:            route.TokenEndpoint(),
		JWKSURI:                  route.JWKSURI(),
		ResponseTypes:            []string{"code"},
		CodeChallengeMethods:     []string{"S256"},
		IDTokenSigningAlgorithms: []string{"RS256"},
		TokenAuthMethods:         []string{"client_secret_basic"},
	})
	if err != nil {
		t.Fatalf("construct integration OIDC metadata: %v", err)
	}
	secrets, err := oidcauth.GenerateSecrets()
	if err != nil {
		t.Fatalf("generate integration OIDC secrets: %v", err)
	}
	digestKeyID, err := oidcauth.NewDigestKeyID("integration-oidc-digest-v1")
	if err != nil {
		t.Fatalf("construct integration OIDC digest key id: %v", err)
	}
	digestKey, err := oidcauth.NewDigestKey(digestKeyID, integrationFilledBytes(0x31, 32))
	if err != nil {
		t.Fatalf("construct integration OIDC digest key: %v", err)
	}
	cipherKeyID, err := oidcauth.NewVerifierEncryptionKeyID("integration-oidc-aead-v1")
	if err != nil {
		t.Fatalf("construct integration OIDC cipher key id: %v", err)
	}
	cipher, err := oidcauth.NewVerifierCipher(cipherKeyID, integrationFilledBytes(0x42, 32))
	if err != nil {
		t.Fatalf("construct integration OIDC verifier cipher: %v", err)
	}
	transactionID, err := oidcauth.ParseTransactionID(ids[0])
	if err != nil {
		t.Fatalf("parse integration OIDC transaction id: %v", err)
	}
	mutationIDs, err := oidcauth.NewMutationIDs(oidcauth.MutationIDParams{
		ChangeID:      parseIntegrationAuthPublicID(t, ids[1]),
		AuditEventID:  parseIntegrationAuthPublicID(t, ids[2]),
		OutboxEventID: parseIntegrationAuthPublicID(t, ids[3]),
	})
	if err != nil {
		t.Fatalf("construct integration OIDC mutation IDs: %v", err)
	}
	createdAt := time.Now().UTC()
	pending, err := oidcauth.NewPending(oidcauth.PendingParams{
		TransactionID:  transactionID,
		Route:          route,
		Metadata:       metadata,
		Secrets:        secrets,
		DigestKey:      digestKey,
		VerifierCipher: cipher,
		MutationIDs:    mutationIDs,
		CreatedAt:      createdAt,
		ExpiresAt:      createdAt.Add(5 * time.Minute),
	})
	if err != nil {
		t.Fatalf("construct integration OIDC pending transaction: %v", err)
	}
	return pending
}

func parseIntegrationAuthPublicID(t *testing.T, value string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(value)
	if err != nil {
		t.Fatalf("parse integration OIDC public id: %v", err)
	}
	return id
}

func integrationFilledBytes(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func rollbackAuthTransactionIntegration(
	ctx context.Context,
	t *testing.T,
	transaction oidcauth.Transaction,
) {
	t.Helper()
	if err := transaction.Rollback(ctx); err != nil {
		t.Errorf("rollback OIDC auth transaction: %v", err)
	}
}

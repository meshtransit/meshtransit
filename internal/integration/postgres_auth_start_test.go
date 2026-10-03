//go:build integration

package integration

import (
	"bytes"
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	adapteroidc "github.com/meshtransit/meshtransit/internal/adapter/oidc"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

func assertPostgreSQLAuthStart(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	store *postgresadapter.AuthTransactionStore,
) {
	t.Helper()
	for _, test := range []struct {
		name          string
		suffix        string
		unknownCommit bool
		appAhead      bool
	}{
		{name: "login start app ahead of DB", suffix: "955", appAhead: true},
		{name: "login start acknowledged", suffix: "956"},
		{name: "login start loses commit ack", suffix: "957", unknownCommit: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			template := integrationAuthTransactionPending(t, integrationAuthRouteParams{
				providerGeneration: 1, recoveryEpoch: 1,
				workspacePublicID: "01890f00-0000-7000-8000-000000000101",
			}, [4]string{
				"01890f00-0000-7000-8000-000000000" + test.suffix,
				"01890f01-0000-7000-8000-000000000" + test.suffix,
				"01890f02-0000-7000-8000-000000000" + test.suffix,
				"01890f03-0000-7000-8000-000000000" + test.suffix,
			})
			transactions := &integrationAuthStartTransactions{store: store, unknownCommit: test.unknownCommit}
			dependencies := integrationAuthStartDependencies(t, template, store, transactions)
			if test.appAhead {
				dependencies.Clock = integrationFailureStartClock{time.Now().UTC().Add(time.Second)}
			}
			service, err := oidcauth.NewStartService(oidcauth.StartOptions{
				RequestTimeout: 10 * time.Second, PendingLifetime: 5 * time.Minute,
				RollbackTimeout: 2 * time.Second, ResolveTimeout: 2 * time.Second,
			}, dependencies)
			if err != nil {
				t.Fatalf("construct integration auth start: %v", err)
			}
			result, err := service.Start(ctx, template.Route())
			if err != nil || !result.IsValid() || result.Created().TransactionID() != template.TransactionID() {
				t.Fatalf("Start() error = %v, want exact confirmed creation", err)
			}
			pending := transactions.pending
			if !pending.IsValid() || transactions.begins != 1 || transactions.creates != 1 || transactions.commits != 1 {
				t.Fatal("login start repeated or lost its exact durable preparation")
			}
			var transactionsCount, auditCount, outboxCount int
			var state string
			if err := adminConnection.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh.auth_transaction WHERE public_id = $1::UUID),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event
     WHERE target_kind = 'auth_transaction' AND target_public_id = $1::UUID),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event
     WHERE aggregate_kind = 'auth_transaction' AND aggregate_public_id = $1::UUID),
    (SELECT state FROM mesh.auth_transaction WHERE public_id = $1::UUID)`,
				pending.TransactionID().String(),
			).Scan(&transactionsCount, &auditCount, &outboxCount, &state); err != nil {
				t.Fatalf("query login-start durable completeness: %v", err)
			}
			if transactionsCount != 1 || auditCount != 1 || outboxCount != 1 || state != "pending" {
				t.Fatal("login start did not commit one pending transaction with audit/outbox")
			}
			replayed, found, err := store.ResolveCommitted(ctx, pending)
			if err != nil || !found || replayed != result.Created() {
				t.Fatalf("durable creation lookup error = %v, want exact login-start evidence", err)
			}
			assertDurableBrowserProof(ctx, t, adminConnection, dependencies, pending, result)
			location, parseErr := url.Parse(result.AuthorizationRequest().Location())
			if parseErr != nil {
				t.Fatal("invalid authorization location")
			}
			browserState, stateErr := oidcauth.ParseState(location.Query().Get("state"))
			if stateErr != nil {
				t.Fatal("invalid authorization state")
			}
			verification, verifyErr := oidcauth.NewBrowserVerificationService(oidcauth.BrowserVerificationOptions{RequestTimeout: 10 * time.Second}, oidcauth.BrowserVerificationDependencies{
				Pending: store, DigestKey: dependencies.DigestKey, VerifierCipher: dependencies.VerifierCipher, Clock: dependencies.Clock,
			})
			if verifyErr != nil {
				t.Fatal(verifyErr)
			}
			if _, verifyErr = verification.VerifyBrowser(ctx, template.Route(), browserState, result.PreAuthCookie()); verifyErr != nil {
				t.Fatal("immediate committed browser proof unavailable", verifyErr)
			}
			assertBrowserProofTerminalErasure(ctx, t, adminConnection, pending,
				"01890f04-0000-7000-8000-000000000"+test.suffix)
		})
	}
}

func assertDurableBrowserProof(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	dependencies oidcauth.StartDependencies,
	pending oidcauth.Pending,
	result oidcauth.StartResult,
) {
	t.Helper()
	var algorithm, keyIdentity string
	var stored, hash []byte
	if err := connection.QueryRow(ctx, `SELECT pkce_verifier_encryption_algorithm,
    pkce_verifier_encryption_key_id, pkce_verifier_ciphertext, binding_semantic_hash
FROM mesh.auth_transaction WHERE public_id = $1::UUID`, pending.TransactionID().String()).Scan(&algorithm, &keyIdentity, &stored, &hash); err != nil {
		t.Fatalf("load durable browser proof: %v", err)
	}
	expectedHash := pending.SemanticHash()
	if algorithm != oidcauth.VerifierEncryptionAlgorithmAES256GCMV1 || !bytes.Equal(hash, expectedHash[:]) || !bytes.Equal(stored, pending.VerifierCiphertext().Bytes()) {
		t.Fatal("durable browser proof changed envelope or semantic binding")
	}
	keyID, err := oidcauth.NewVerifierEncryptionKeyID(keyIdentity)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := oidcauth.NewCiphertext(keyID, stored)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := pending.Route().Binding(pending.TransactionID())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := dependencies.VerifierCipher.OpenBrowser(binding, ciphertext)
	if err != nil || !dependencies.DigestKey.VerifyPreAuthCookie(binding, result.PreAuthCookie(), proof.CookieDigest()) {
		t.Fatal("released cookie does not match durable browser proof")
	}
	if dependencies.DigestKey.VerifyPreAuthCookie(binding, oidcauth.PreAuthCookie{}, proof.CookieDigest()) {
		t.Fatal("durable proof accepts absent browser binding")
	}
}

func assertBrowserProofTerminalErasure(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	pending oidcauth.Pending,
	changePublicID string,
) {
	t.Helper()
	for _, test := range []struct {
		name   string
		retain bool
	}{
		{name: "terminal retains encrypted proof rejected", retain: true},
		{name: "terminal clears complete encrypted proof"},
	} {
		t.Run(test.name, func(t *testing.T) {
			transaction, err := connection.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackIntegrationTransaction(ctx, t, transaction)
			setIntegrationChange(ctx, t, transaction, changePublicID)
			_, err = transaction.Exec(ctx, `UPDATE mesh.auth_transaction SET
    state = 'failed', consumed_at = GREATEST(pg_catalog.transaction_timestamp(), created_at),
    failure_class = 'browser_binding_failed', version = version + 1,
    updated_at = GREATEST(pg_catalog.transaction_timestamp(), updated_at),
    pkce_verifier_encryption_algorithm = CASE WHEN $2 THEN pkce_verifier_encryption_algorithm ELSE NULL END,
    pkce_verifier_encryption_key_id = CASE WHEN $2 THEN pkce_verifier_encryption_key_id ELSE NULL END,
    pkce_verifier_ciphertext = CASE WHEN $2 THEN pkce_verifier_ciphertext ELSE NULL END
WHERE public_id = $1::UUID`, pending.TransactionID().String(), test.retain)
			if test.retain {
				assertPostgreSQLConstraint(t, err, "auth_transaction_pkce_check")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var erased bool
			if err := transaction.QueryRow(ctx, `SELECT state = 'failed'
    AND pkce_verifier_encryption_algorithm IS NULL
    AND pkce_verifier_encryption_key_id IS NULL
    AND pkce_verifier_ciphertext IS NULL
FROM mesh.auth_transaction WHERE public_id = $1::UUID`, pending.TransactionID().String()).Scan(&erased); err != nil {
				t.Fatal(err)
			}
			if !erased {
				t.Fatal("terminal state retains cookie or PKCE evidence")
			}
			// Roll back this schema-contract probe. It is not a production expiry
			// worker, and does not commit an unaudited lifecycle mutation.
		})
	}
}

func integrationAuthStartDependencies(
	t *testing.T,
	template oidcauth.Pending,
	store *postgresadapter.AuthTransactionStore,
	transactions *integrationAuthStartTransactions,
) oidcauth.StartDependencies {
	t.Helper()
	keyID, err := oidcauth.NewDigestKeyID("integration-oidc-digest-v1")
	if err != nil {
		t.Fatal(err)
	}
	key, err := oidcauth.NewDigestKey(keyID, integrationFilledBytes(0x31, 32))
	if err != nil {
		t.Fatal(err)
	}
	cipherID, err := oidcauth.NewVerifierEncryptionKeyID("integration-oidc-aead-v1")
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := oidcauth.NewVerifierCipher(cipherID, integrationFilledBytes(0x42, 32))
	if err != nil {
		t.Fatal(err)
	}
	return oidcauth.StartDependencies{
		Metadata: integrationAuthStartMetadata{}, Transactions: transactions, Committed: store, CreationClock: store,
		IDs: integrationAuthStartIDs{template: template}, Secrets: oidcauth.SystemSecrets{},
		Clock: oidcauth.SystemStartClock{}, Observer: adapteroidc.NewStartTelemetry(),
		DigestKey: key, VerifierCipher: cipher,
	}
}

type integrationAuthStartMetadata struct{}

func (integrationAuthStartMetadata) Resolve(_ context.Context, route oidcauth.Route) (oidcauth.Metadata, error) {
	return oidcauth.NewMetadata(oidcauth.MetadataParams{
		Issuer: route.Issuer(), AuthorizationEndpoint: route.AuthorizationEndpoint(),
		TokenEndpoint: route.TokenEndpoint(), JWKSURI: route.JWKSURI(),
		ResponseTypes: []string{"code"}, CodeChallengeMethods: []string{"S256"},
		IDTokenSigningAlgorithms: route.AllowedAlgorithms(), TokenAuthMethods: []string{route.ClientAuthMethod()},
	})
}

type integrationAuthStartIDs struct{ template oidcauth.Pending }

func (ids integrationAuthStartIDs) NewStartIDs() (oidcauth.TransactionID, oidcauth.MutationIDs, error) {
	return ids.template.TransactionID(), ids.template.MutationIDs(), nil
}

type integrationAuthStartTransactions struct {
	store         *postgresadapter.AuthTransactionStore
	pending       oidcauth.Pending
	unknownCommit bool
	begins        int
	creates       int
	commits       int
}

func (transactions *integrationAuthStartTransactions) Begin(ctx context.Context, route oidcauth.Route) (oidcauth.Transaction, error) {
	transactions.begins++
	transaction, err := transactions.store.Begin(ctx, route)
	if err != nil {
		return nil, err
	}
	return &integrationAuthStartTransaction{transaction: transaction, owner: transactions}, nil
}

type integrationAuthStartTransaction struct {
	transaction oidcauth.Transaction
	owner       *integrationAuthStartTransactions
}

func (transaction *integrationAuthStartTransaction) Create(ctx context.Context, pending oidcauth.Pending) (oidcauth.Created, error) {
	transaction.owner.creates++
	transaction.owner.pending = pending
	return transaction.transaction.Create(ctx, pending)
}

func (transaction *integrationAuthStartTransaction) Commit(ctx context.Context) error {
	transaction.owner.commits++
	if err := transaction.transaction.Commit(ctx); err != nil {
		return err
	}
	if transaction.owner.unknownCommit {
		// PostgreSQL has really committed; only the acknowledgement is hidden.
		return postgresadapter.ErrAuthTransactionCommitOutcomeUnknown
	}
	return nil
}

func (transaction *integrationAuthStartTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}

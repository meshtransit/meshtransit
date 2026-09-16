//go:build integration

package integration

import (
	"context"
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
	}{
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
		Metadata: integrationAuthStartMetadata{}, Transactions: transactions, Committed: store,
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

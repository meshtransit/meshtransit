package postgres

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

type authTransactionTestCall struct {
	query     string
	arguments []any
}

type fakeAuthTransactionDatabase struct {
	transactions []*fakeAuthTransactionDatabaseTransaction
	readOnly     []bool
	beginErr     error
}

func (database *fakeAuthTransactionDatabase) Begin(
	_ context.Context,
	readOnly bool,
) (authTransactionDatabaseTransaction, error) {
	database.readOnly = append(database.readOnly, readOnly)
	if database.beginErr != nil {
		return nil, database.beginErr
	}
	if len(database.transactions) == 0 {
		return nil, errors.New("no queued auth transaction")
	}
	transaction := database.transactions[0]
	database.transactions = database.transactions[1:]
	return transaction, nil
}

type fakeAuthTransactionDatabaseTransaction struct {
	rows          map[string][]authTransactionRow
	execErrors    map[string][]error
	calls         []authTransactionTestCall
	commitErr     error
	rollbackErr   error
	commitCalls   int
	rollbackCalls int
}

func newFakeAuthTransactionDatabaseTransaction() *fakeAuthTransactionDatabaseTransaction {
	return &fakeAuthTransactionDatabaseTransaction{
		rows:       make(map[string][]authTransactionRow),
		execErrors: make(map[string][]error),
	}
}

func (transaction *fakeAuthTransactionDatabaseTransaction) Exec(
	_ context.Context,
	query string,
	arguments ...any,
) error {
	transaction.record(query, arguments)
	queued := transaction.execErrors[query]
	if len(queued) == 0 {
		return nil
	}
	transaction.execErrors[query] = queued[1:]
	return queued[0]
}

func (transaction *fakeAuthTransactionDatabaseTransaction) QueryRow(
	_ context.Context,
	query string,
	arguments ...any,
) authTransactionRow {
	transaction.record(query, arguments)
	queued := transaction.rows[query]
	if len(queued) == 0 {
		return authTransactionTestRow{err: fmt.Errorf("unexpected auth query: %s", query)}
	}
	transaction.rows[query] = queued[1:]
	return queued[0]
}

func (transaction *fakeAuthTransactionDatabaseTransaction) Commit(context.Context) error {
	transaction.commitCalls++
	return transaction.commitErr
}

func (transaction *fakeAuthTransactionDatabaseTransaction) Rollback(context.Context) error {
	transaction.rollbackCalls++
	return transaction.rollbackErr
}

func (transaction *fakeAuthTransactionDatabaseTransaction) enqueueRow(
	query string,
	row authTransactionRow,
) {
	transaction.rows[query] = append(transaction.rows[query], row)
}

func (transaction *fakeAuthTransactionDatabaseTransaction) record(query string, arguments []any) {
	transaction.calls = append(transaction.calls, authTransactionTestCall{
		query:     query,
		arguments: append([]any(nil), arguments...),
	})
}

type authTransactionTestRow struct {
	scan func(...any) error
	err  error
}

func (row authTransactionTestRow) Scan(destinations ...any) error {
	if row.err != nil {
		return row.err
	}
	if row.scan == nil {
		return nil
	}
	return row.scan(destinations...)
}

func testAuthTransactionOptions() AuthTransactionOptions {
	return AuthTransactionOptions{
		StatementTimeout: 5 * time.Second,
		LockTimeout:      time.Second,
		IdleTimeout:      10 * time.Second,
	}
}

func authTransactionPendingFixture(t *testing.T) oidcauth.Pending {
	t.Helper()
	pending, _ := authTransactionBrowserFixture(t)
	return pending
}

func authTransactionBrowserFixture(t *testing.T) (oidcauth.Pending, oidcauth.Secrets) {
	t.Helper()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("deployment.ParseID() error = %v", err)
	}
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000002")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	providerID, err := oidcauth.ParseProviderID("01890f00-0000-7000-8000-000000000003")
	if err != nil {
		t.Fatalf("oidcauth.ParseProviderID() error = %v", err)
	}
	clientID, err := oidcauth.ParseClientID("01890f00-0000-7000-8000-000000000004")
	if err != nil {
		t.Fatalf("oidcauth.ParseClientID() error = %v", err)
	}
	// #nosec G101 -- synthetic OIDC metadata contains only an auth-method identifier, no credentials.
	route, err := oidcauth.NewRoute(oidcauth.RouteParams{
		DeploymentID:          deploymentID,
		WorkspaceID:           workspaceID,
		ProviderID:            providerID,
		ClientID:              clientID,
		ProviderGeneration:    3,
		RecoveryEpoch:         2,
		Issuer:                "https://login.example.test/realms/meshtransit",
		DiscoveryURI:          "https://login.example.test/realms/meshtransit/.well-known/openid-configuration",
		AuthorizationEndpoint: "https://login.example.test/realms/meshtransit/protocol/openid-connect/auth",
		TokenEndpoint:         "https://login.example.test/realms/meshtransit/protocol/openid-connect/token",
		JWKSURI:               "https://login.example.test/realms/meshtransit/protocol/openid-connect/certs",
		OIDCClientID:          "meshtransit-web",
		ClientKind:            "confidential",
		ClientAuthMethod:      "client_secret_basic",
		Scopes:                []string{"openid", "profile", "email"},
		AllowedAlgorithms:     []string{"RS256"},
		RedirectID:            "web.primary",
		RedirectURI:           "https://control.example.test/auth/callback",
		ReturnRouteID:         "console.home",
	})
	if err != nil {
		t.Fatalf("oidcauth.NewRoute() error = %v", err)
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
		t.Fatalf("oidcauth.NewMetadata() error = %v", err)
	}
	secrets, err := oidcauth.GenerateSecrets()
	if err != nil {
		t.Fatalf("oidcauth.GenerateSecrets() error = %v", err)
	}
	digestKeyID, err := oidcauth.NewDigestKeyID("oidc-digest-v1")
	if err != nil {
		t.Fatalf("oidcauth.NewDigestKeyID() error = %v", err)
	}
	digestKey, err := oidcauth.NewDigestKey(digestKeyID, bytesOf(0x41, 32))
	if err != nil {
		t.Fatalf("oidcauth.NewDigestKey() error = %v", err)
	}
	cipherKeyID, err := oidcauth.NewVerifierEncryptionKeyID("oidc-verifier-v1")
	if err != nil {
		t.Fatalf("oidcauth.NewVerifierEncryptionKeyID() error = %v", err)
	}
	cipher, err := oidcauth.NewVerifierCipher(cipherKeyID, bytesOf(0x52, 32))
	if err != nil {
		t.Fatalf("oidcauth.NewVerifierCipher() error = %v", err)
	}
	transactionID, err := oidcauth.ParseTransactionID("01890f00-0000-7000-8000-000000000005")
	if err != nil {
		t.Fatalf("oidcauth.ParseTransactionID() error = %v", err)
	}
	mutationIDs, err := oidcauth.NewMutationIDs(oidcauth.MutationIDParams{
		ChangeID:      mustAuthTransactionPublicID(t, "01890f00-0000-7000-8000-000000000006"),
		AuditEventID:  mustAuthTransactionPublicID(t, "01890f00-0000-7000-8000-000000000007"),
		OutboxEventID: mustAuthTransactionPublicID(t, "01890f00-0000-7000-8000-000000000008"),
	})
	if err != nil {
		t.Fatalf("oidcauth.NewMutationIDs() error = %v", err)
	}
	createdAt := time.Date(2026, time.September, 16, 4, 0, 0, 123456789, time.UTC)
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
		t.Fatalf("oidcauth.NewPending() error = %v", err)
	}
	return pending, secrets
}

func enqueueAuthTransactionCreation(
	transaction *fakeAuthTransactionDatabaseTransaction,
	pending oidcauth.Pending,
) {
	transaction.enqueueRow(createAuthTransactionSQL, authTransactionCreatedRow(pending))
	transaction.enqueueRow(lockAuthTransactionAuditStreamSQL, authTransactionTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 51

			*destinations[1].(*int64) = 7
			*destinations[2].(*[]byte) = make([]byte, 32)
			return nil
		},
	})
	transaction.enqueueRow(appendAuthTransactionEvidenceSQL, authTransactionTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*int64) = 7
			return nil
		},
	})
}

func authTransactionCreatedRow(pending oidcauth.Pending) authTransactionTestRow {
	return authTransactionTestRow{
		scan: func(destinations ...any) error {
			*destinations[0].(*string) = pending.TransactionID().String()
			*destinations[1].(*int64) = 1
			*destinations[2].(*time.Time) = pending.CreatedAt()
			*destinations[3].(*time.Time) = pending.ExpiresAt()
			return nil
		},
	}
}

func mustAuthTransactionPublicID(t *testing.T, value string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(value)
	if err != nil {
		t.Fatalf("publicid.Parse() error = %v", err)
	}
	return id
}

func bytesOf(value byte, count int) []byte {
	encoded := make([]byte, count)
	for index := range encoded {
		encoded[index] = value
	}
	return encoded
}

func secretEncodings(pending oidcauth.Pending) []string {
	location := pending.AuthorizationRequest().Location()
	stateDigest := pending.StateDigest().Bytes()
	nonceDigest := pending.NonceDigest().Bytes()
	return []string{
		location,
		base64.RawURLEncoding.EncodeToString(stateDigest[:]),
		base64.RawURLEncoding.EncodeToString(nonceDigest[:]),
	}
}

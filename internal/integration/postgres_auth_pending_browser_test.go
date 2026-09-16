//go:build integration

package integration

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

const integrationPendingBrowserCountSQL = `SELECT pg_catalog.count(*)
FROM mesh_ops.load_oidc_pending_browser_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::BIGINT, $6::BIGINT,
    $7::TEXT, $8::TEXT, $9::TEXT, $10::TEXT, $11::TEXT,
    $12::TEXT, $13::TEXT, $14::TEXT[], $15::TEXT[], $16::TEXT,
    $17::TEXT, $18::TEXT, $19::BYTEA, $20::TEXT, $21::TEXT
)`

func assertPostgreSQLPendingBrowserEvidence(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn, pool *postgresadapter.Pool) {
	t.Helper()
	template := integrationAuthTransactionPending(t, integrationAuthRouteParams{
		providerGeneration: 1, recoveryEpoch: 1, workspacePublicID: "01890f00-0000-7000-8000-000000000101",
	}, [4]string{
		"01890f00-0000-7000-8000-000000000966", "01890f01-0000-7000-8000-000000000966",
		"01890f02-0000-7000-8000-000000000966", "01890f03-0000-7000-8000-000000000966",
	})
	store, err := postgresadapter.NewAuthTransactionStore(pool, postgresadapter.AuthTransactionOptions{
		StatementTimeout: 5 * time.Second, LockTimeout: time.Second, IdleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	transactions := &integrationAuthStartTransactions{store: store}
	dependencies := integrationAuthStartDependencies(t, template, store, transactions)
	start, err := oidcauth.NewStartService(oidcauth.StartOptions{
		RequestTimeout: 10 * time.Second, PendingLifetime: 5 * time.Minute, RollbackTimeout: 2 * time.Second, ResolveTimeout: 2 * time.Second,
	}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	started, err := start.Start(ctx, template.Route())
	if err != nil {
		t.Fatal(err)
	}
	// This explicit authorization-URL boundary is synthetic test-only material.
	authorizationURL, err := url.Parse(started.AuthorizationRequest().Location())
	if err != nil {
		t.Fatal("invalid synthetic authorization URL")
	}
	state, err := oidcauth.ParseState(authorizationURL.Query().Get("state"))
	if err != nil {
		t.Fatal("invalid synthetic authorization state")
	}
	before := authAdmissionAuthorityCounts(ctx, t, admin)
	for range 2 {
		verify, err := oidcauth.NewBrowserVerificationService(oidcauth.BrowserVerificationOptions{RequestTimeout: 10 * time.Second}, oidcauth.BrowserVerificationDependencies{
			Pending: store, DigestKey: dependencies.DigestKey, VerifierCipher: dependencies.VerifierCipher, Clock: oidcauth.SystemStartClock{},
		})
		if err != nil {
			t.Fatal(err)
		}
		verified, err := verify.VerifyBrowser(ctx, template.Route(), state, started.PreAuthCookie())
		if err != nil || !verified.IsValid() || verified.Snapshot().SemanticHash() != transactions.pending.SemanticHash() {
			clockBefore := time.Now().UTC()
			var databaseNow time.Time
			if clockErr := admin.QueryRow(ctx, `SELECT pg_catalog.clock_timestamp()`).Scan(&databaseNow); clockErr != nil {
				t.Fatalf("durable browser verification error=%v; clock diagnostic failed", err)
			}
			clockAfter := time.Now().UTC()
			digest, digestErr := dependencies.DigestKey.State(
				template.Route().DeploymentID(), template.Route().RecoveryEpoch(), state,
			)
			if digestErr != nil {
				t.Fatal("browser verification diagnostic digest failed")
			}
			snapshot, found, loadErr := store.LoadPending(ctx, template.Route(), digest)
			// Only safe diagnostics escape; never log state, cookie, ciphertext or code.
			t.Fatalf(
				"durable browser verification error=%v; found=%t load_failed=%t route_match=%t "+
					"database_clock_offset_bounds=[%s,%s] created_after_database_now=%t",
				err,
				found,
				loadErr != nil,
				snapshot.MatchesRoute(template.Route()),
				databaseNow.Sub(clockAfter),
				databaseNow.Sub(clockBefore),
				transactions.pending.CreatedAt().After(databaseNow),
			)
		}
		other, err := oidcauth.GenerateSecrets()
		if err != nil {
			t.Fatal(err)
		}
		if result, err := verify.VerifyBrowser(ctx, template.Route(), state, other.PreAuthCookie()); !errors.Is(err, oidcauth.ErrBrowserVerificationRejected) || result.IsValid() {
			t.Fatal("URL-only possession verified browser")
		}
	}
	assertPendingBrowserPrivileges(ctx, t, admin)
	arguments := integrationLoginRouteArguments(template.Route())
	stateDigest := transactions.pending.StateDigest().Bytes()
	arguments = append(arguments, transactions.pending.StateDigest().Algorithm(), transactions.pending.StateDigest().KeyID().String(),
		stateDigest[:], template.Route().RedirectID(), template.Route().ReturnRouteID())
	for _, candidate := range []struct {
		name  string
		index int
		value any
	}{
		{"other deployment", 0, "01890f00-0000-7000-8000-000000000002"},
		{"other workspace", 1, "01890f00-0000-7000-8000-000000000102"},
		{"other provider", 2, "01890f00-0000-7000-8000-000000000602"},
		{"other client", 3, "01890f00-0000-7000-8000-000000000622"},
		{"stale generation", 4, int64(2)}, {"stale epoch", 5, int64(2)},
		{"issuer", 6, "https://other.example.test/issuer"}, {"discovery", 7, "https://other.example.test/discovery"},
		{"authorization", 8, "https://other.example.test/auth"}, {"token", 9, "https://other.example.test/token"},
		{"jwks", 10, "https://other.example.test/jwks"}, {"client id", 11, "other-client"},
		{"auth method", 12, "private_key_jwt"}, {"scopes", 13, []string{"profile", "openid"}},
		{"algorithm", 14, []string{"ES256"}}, {"callback", 15, "https://console.example.test/other-callback"},
		{"digest algorithm", 16, "unsupported"}, {"digest key", 17, "other-key"}, {"digest bytes", 18, []byte{1}},
		{"redirect label", 19, "other-callback"}, {"return label", 20, "other-return"},
	} {
		t.Run("pending browser "+candidate.name, func(t *testing.T) {
			changed := append([]any(nil), arguments...)
			changed[candidate.index] = candidate.value
			transaction, err := runtime.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackIntegrationTransaction(ctx, t, transaction)
			if _, err := transaction.Exec(ctx, `SELECT pg_catalog.set_config('mesh.requested_workspace_public_id',
    '01890f00-0000-7000-8000-000000000102', TRUE)`); err != nil {
				t.Fatal(err)
			}
			assertPendingBrowserCount(ctx, t, transaction, changed, 0)
			assertAdmissionScopeCleared(ctx, t, transaction)
		})
	}
	transaction, err := runtime.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	assertPendingBrowserCount(ctx, t, transaction, arguments, 1)
	assertAdmissionScopeCleared(ctx, t, transaction)
	rollbackIntegrationTransaction(ctx, t, transaction)
	for _, candidate := range []struct{ name, query string }{
		{"consuming", `UPDATE mesh.auth_transaction SET state='consuming', version=version+1,
    consumed_at=pg_catalog.transaction_timestamp(), updated_at=GREATEST(pg_catalog.transaction_timestamp(), updated_at)
WHERE public_id='01890f00-0000-7000-8000-000000000966'::UUID`},
		{"terminal expired", `UPDATE mesh.auth_transaction SET state='expired', version=version+1,
    consumed_at=pg_catalog.transaction_timestamp(), failure_class='expired',
    pkce_verifier_encryption_algorithm=NULL, pkce_verifier_encryption_key_id=NULL, pkce_verifier_ciphertext=NULL,
    updated_at=GREATEST(pg_catalog.transaction_timestamp(), updated_at)
WHERE public_id='01890f00-0000-7000-8000-000000000966'::UUID`},
		{"provider revoked", `UPDATE mesh.identity_provider SET state='suspended', version=version+1,
    updated_at=GREATEST(pg_catalog.transaction_timestamp(), updated_at) WHERE id=601`},
		{"deployment recovery changed", `UPDATE mesh.deployment SET recovery_epoch=2, version=version+1,
    updated_at=GREATEST(pg_catalog.transaction_timestamp(), updated_at) WHERE id=1`},
	} {
		t.Run("pending browser "+candidate.name, func(t *testing.T) {
			probe, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Schema-contract probes intentionally ROLLBACK. Never commit authority
			// mutations without the required immutable audit/outbox coverage.
			defer rollbackIntegrationTransaction(ctx, t, probe)
			if _, err := probe.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id',
    '01890f01-0000-7000-8000-000000000967', TRUE)`); err != nil {
				t.Fatal(err)
			}
			if _, err := probe.Exec(ctx, candidate.query); err != nil {
				t.Fatal(err)
			}
			assertPendingBrowserCount(ctx, t, probe, arguments, 0)
			assertAdmissionScopeCleared(ctx, t, probe)
		})
	}
	if after := authAdmissionAuthorityCounts(ctx, t, admin); before != after {
		t.Fatal("pending browser reads changed durable authority/audit/outbox/revisions")
	}
}

func assertPendingBrowserCount(ctx context.Context, t *testing.T, transaction pgx.Tx, arguments []any, expected int64) {
	t.Helper()
	var count int64
	if err := transaction.QueryRow(ctx, integrationPendingBrowserCountSQL, arguments...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != expected {
		t.Fatalf("pending browser count=%d want=%d", count, expected)
	}
}

func assertPendingBrowserPrivileges(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var hardened, runtimeAllowed, workerAllowed, observerAllowed, tableAllowed bool
	if err := admin.QueryRow(ctx, `SELECT
    function.prosecdef AND NOT owner.rolsuper AND NOT owner.rolbypassrls AND owner.rolname='mesh_migrator'
      AND function.proconfig @> ARRAY['search_path=pg_catalog, mesh, mesh_ops']::TEXT[],
    pg_catalog.has_function_privilege('mesh_runtime', function.oid, 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_worker', function.oid, 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_observer', function.oid, 'EXECUTE'),
    pg_catalog.has_table_privilege('mesh_runtime', 'mesh.auth_transaction', 'SELECT')
      OR pg_catalog.has_table_privilege('mesh_runtime', 'mesh.auth_transaction', 'UPDATE')
FROM pg_catalog.pg_proc AS function
JOIN pg_catalog.pg_namespace AS schema ON schema.oid=function.pronamespace
JOIN pg_catalog.pg_roles AS owner ON owner.oid=function.proowner
WHERE schema.nspname='mesh_ops' AND function.proname='load_oidc_pending_browser_v1'
`).Scan(&hardened, &runtimeAllowed, &workerAllowed, &observerAllowed, &tableAllowed); err != nil {
		t.Fatal(err)
	}
	if !hardened || !runtimeAllowed || workerAllowed || observerAllowed || tableAllowed {
		t.Fatal("pending browser privileges widened")
	}
}

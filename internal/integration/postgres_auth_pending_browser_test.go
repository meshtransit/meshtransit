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
FROM mesh_ops.load_oidc_pending_browser_v2(
    $1::UUID, $2::UUID, $3::UUID, $4::BIGINT, $5::BIGINT,
    $6::TEXT, $7::TEXT, $8::TEXT, $9::TEXT, $10::TEXT,
    $11::TEXT, $12::TEXT, $13::TEXT[], $14::TEXT[], $15::TEXT,
    $16::TEXT, $17::TEXT, $18::BYTEA, $19::TEXT, $20::TEXT
)`

// integrationPendingBrowserV1CountSQL is the retained rollback-era loader. It
// proves a Workspace-scoped copy is otherwise loadable, so a v2 miss is scope.
const integrationPendingBrowserV1CountSQL = `SELECT pg_catalog.count(*)
FROM mesh_ops.load_oidc_pending_browser_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::BIGINT, $6::BIGINT,
    $7::TEXT, $8::TEXT, $9::TEXT, $10::TEXT, $11::TEXT,
    $12::TEXT, $13::TEXT, $14::TEXT[], $15::TEXT[], $16::TEXT,
    $17::TEXT, $18::TEXT, $19::BYTEA, $20::TEXT, $21::TEXT
)`

// integrationWorkspaceScopedAuthCopySQL inserts, only inside rollback probes,
// a v1-shaped pending copy (workspace_id NOT NULL) of one Workspace-less
// browser transaction with fresh identity and state/nonce digests.
const integrationWorkspaceScopedAuthCopySQL = `INSERT INTO mesh.auth_transaction OVERRIDING SYSTEM VALUE
SELECT (pg_catalog.jsonb_populate_record(NULL::mesh.auth_transaction,
    pg_catalog.to_jsonb(source) || pg_catalog.jsonb_build_object(
        'id', (SELECT pg_catalog.max(existing.id) + 1000 FROM mesh.auth_transaction AS existing),
        'public_id', $2::UUID, 'workspace_id', $3::BIGINT,
        'state_digest', '\x' || pg_catalog.encode($4::BYTEA, 'hex'),
        'nonce_digest', '\x' || pg_catalog.encode($4::BYTEA, 'hex'),
        'state', 'pending', 'version', 1, 'consumed_at', NULL,
        'updated_at', source.created_at
    ))).*
FROM mesh.auth_transaction AS source
WHERE source.public_id = $1::UUID AND source.workspace_id IS NULL`

// insertIntegrationWorkspaceScopedAuthCopy creates the v1-shaped copy and,
// when consume is set, moves it to the source's exact consuming claim.
func insertIntegrationWorkspaceScopedAuthCopy(
	ctx context.Context, t *testing.T, transaction pgx.Tx,
	sourcePublicID, copyPublicID string, digest []byte, consume bool,
) {
	t.Helper()
	tag, err := transaction.Exec(ctx, integrationWorkspaceScopedAuthCopySQL, sourcePublicID, copyPublicID, int64(101), digest)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("insert Workspace-scoped auth copy rows=%d: %v", tag.RowsAffected(), err)
	}
	if !consume {
		return
	}
	tag, err = transaction.Exec(ctx, `UPDATE mesh.auth_transaction AS copy
SET state = 'consuming', version = 2, consumed_at = source.consumed_at,
    updated_at = GREATEST(copy.updated_at, source.consumed_at)
FROM mesh.auth_transaction AS source
WHERE copy.public_id = $2::UUID AND source.public_id = $1::UUID
  AND source.state = 'consuming' AND source.consumed_at IS NOT NULL`, sourcePublicID, copyPublicID)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatalf("claim Workspace-scoped auth copy rows=%d: %v", tag.RowsAffected(), err)
	}
}

func assertPostgreSQLPendingBrowserEvidence(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn, pool *postgresadapter.Pool) {
	t.Helper()
	template := integrationAuthTransactionPending(t, integrationAuthRouteParams{
		providerGeneration: 1, recoveryEpoch: 1,
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
		{"other provider", 1, "01890f00-0000-7000-8000-000000000602"},
		{"other client", 2, "01890f00-0000-7000-8000-000000000622"},
		{"stale generation", 3, int64(2)}, {"stale epoch", 4, int64(2)},
		{"issuer", 5, "https://other.example.test/issuer"}, {"discovery", 6, "https://other.example.test/discovery"},
		{"authorization", 7, "https://other.example.test/auth"}, {"token", 8, "https://other.example.test/token"},
		{"jwks", 9, "https://other.example.test/jwks"}, {"client id", 10, "other-client"},
		{"auth method", 11, "private_key_jwt"}, {"scopes", 12, []string{"profile", "openid"}},
		{"algorithm", 13, []string{"ES256"}}, {"callback", 14, "https://console.example.test/other-callback"},
		{"digest algorithm", 15, "unsupported"}, {"digest key", 16, "other-key"}, {"digest bytes", 17, []byte{1}},
		{"redirect label", 18, "other-callback"}, {"return label", 19, "other-return"},
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
	t.Run("pending browser Workspace-scoped v1 transaction", func(t *testing.T) {
		probe, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// Rollback-only: a v1 row (workspace_id NOT NULL) never becomes a v2 login.
		defer rollbackIntegrationTransaction(ctx, t, probe)
		if _, err := probe.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id',
    '01890f01-0000-7000-8000-000000000968', TRUE)`); err != nil {
			t.Fatal(err)
		}
		copyDigest := integrationFilledBytes(0x68, 32)
		insertIntegrationWorkspaceScopedAuthCopy(ctx, t, probe, template.TransactionID().String(),
			"01890f00-0000-7000-8000-000000000968", copyDigest, false)
		scoped := append([]any(nil), arguments...)
		scoped[17] = copyDigest
		assertPendingBrowserCount(ctx, t, probe, scoped, 0)
		assertAdmissionScopeCleared(ctx, t, probe)
		legacy := append([]any{scoped[0], "01890f00-0000-7000-8000-000000000101"}, scoped[1:]...)
		var loadable int64
		if err := probe.QueryRow(ctx, integrationPendingBrowserV1CountSQL, legacy...).Scan(&loadable); err != nil {
			t.Fatal(err)
		}
		if loadable != 1 {
			t.Fatalf("Workspace-scoped control copy loadable through v1 = %d, want 1", loadable)
		}
	})
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
WHERE schema.nspname='mesh_ops' AND function.proname='load_oidc_pending_browser_v2'
`).Scan(&hardened, &runtimeAllowed, &workerAllowed, &observerAllowed, &tableAllowed); err != nil {
		t.Fatal(err)
	}
	if !hardened || !runtimeAllowed || workerAllowed || observerAllowed || tableAllowed {
		t.Fatal("pending browser privileges widened")
	}
}

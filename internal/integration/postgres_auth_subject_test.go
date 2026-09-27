//go:build integration

package integration

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	adapteroidc "github.com/meshtransit/meshtransit/internal/adapter/oidc"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

const integrationSubjectCountSQL = `SELECT pg_catalog.count(*) FROM mesh_ops.resolve_oidc_login_subject_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,
    $7::TEXT,$8::TEXT,$9::TEXT,$10::TEXT,$11::TEXT,$12::TEXT,$13::TEXT,$14::TEXT[],$15::TEXT[],$16::TEXT,
    $17::UUID,$18::BIGINT,$19::BYTEA,$20::TIMESTAMPTZ,$21::TEXT,$22::TEXT,
    $23::TEXT,$24::TEXT,$25::BYTEA,$26::TEXT,$27::BYTEA)`

func assertPostgreSQLLoginSubjectResolution(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn, pool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewAuthTransactionStore(pool, postgresadapter.AuthTransactionOptions{
		StatementTimeout: 10 * time.Second, LockTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	assertLoginSubjectPrivileges(ctx, t, admin)
	exchange, route := integrationSubjectExchange(ctx, t, store)
	active, previous := integrationSubjectKey(t, "integration-subject-active-v1", 0x51), integrationSubjectKey(t, "integration-subject-previous-v1", 0x52)
	keys, err := oidcauth.NewSubjectKeyring(active, previous)
	if err != nil {
		t.Fatal(err)
	}
	digests, err := keys.Digests(route, exchange.Identity())
	if err != nil {
		t.Fatal(err)
	}
	query, err := oidcauth.NewSubjectLookup(exchange.Claimed(), digests)
	if err != nil {
		t.Fatal(err)
	}
	seedLoginSubjectFixture(ctx, t, admin, digests[1], false)
	before := authAdmissionAuthorityCounts(ctx, t, admin)
	if result, err := store.ResolveLoginSubject(ctx, query); !errors.Is(err, oidcauth.ErrSubjectResolutionRejected) || result.IsValid() {
		t.Fatalf("missing exact login membership did not return closed rejection: %v", err)
	}
	if authAdmissionAuthorityCounts(ctx, t, admin) != before {
		t.Fatal("missing membership provisioned authority")
	}
	seedLoginSubjectFixture(ctx, t, admin, digests[1], true)
	before = authAdmissionAuthorityCounts(ctx, t, admin)
	var lastSeenBefore time.Time
	if err := admin.QueryRow(ctx, `SELECT last_seen_at FROM mesh.identity_subject WHERE public_id='01890f00-0000-7000-8000-000000000fa0'`).Scan(&lastSeenBefore); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		service, err := oidcauth.NewSubjectResolutionService(oidcauth.SubjectResolutionOptions{RequestTimeout: 10 * time.Second, MaxConcurrent: 2}, oidcauth.SubjectResolutionDependencies{
			Subjects: store, Keys: keys, Clock: oidcauth.SystemStartClock{}, Observer: adapteroidc.NewSubjectTelemetry(),
		})
		if err != nil {
			t.Fatal(err)
		}
		result, err := service.ResolveBrowser(ctx, exchange)
		if err != nil || !result.IsValid() || result.Digest() != digests[1] || result.MembershipID().String() != "01890f00-0000-7000-8000-000000000fa1" {
			t.Fatal("independent service failed exact previous-key resolution")
		}
	}
	assertLoginSubjectArguments(ctx, t, runtime, query)
	assertLoginSubjectRevocation(ctx, t, admin, query)
	assertLoginSubjectAmbiguity(ctx, t, admin, query)
	assertLoginSubjectLiveClockAndTerminalClaim(ctx, t, admin, query)
	var lastSeenAfter time.Time
	if err := admin.QueryRow(ctx, `SELECT last_seen_at FROM mesh.identity_subject WHERE public_id='01890f00-0000-7000-8000-000000000fa0'`).Scan(&lastSeenAfter); err != nil {
		t.Fatal(err)
	}
	if before != authAdmissionAuthorityCounts(ctx, t, admin) || !lastSeenBefore.Equal(lastSeenAfter) {
		t.Fatal("lookup changed authority, evidence or last-seen")
	}
	var grants, sessions int64
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh.role_binding WHERE workspace_id=101 AND principal_id=11),
    (SELECT pg_catalog.count(*) FROM mesh.account_session WHERE identity_subject_id=(SELECT id FROM mesh.identity_subject WHERE public_id='01890f00-0000-7000-8000-000000000fa0'))`).Scan(&grants, &sessions); err != nil {
		t.Fatal(err)
	}
	if grants != 0 || sessions != 0 {
		t.Fatal("lookup granted a role or Session")
	}
}

func integrationSubjectExchange(ctx context.Context, t *testing.T, store *postgresadapter.AuthTransactionStore) (oidcauth.ExchangeResult, oidcauth.Route) {
	return integrationSubjectExchangeWithProfile(ctx, t, store, "fa2", integrationSubjectProfile{})
}

func integrationSubjectExchangeWithProfile(ctx context.Context, t *testing.T, store *postgresadapter.AuthTransactionStore, suffix string, profile integrationSubjectProfile) (oidcauth.ExchangeResult, oidcauth.Route) {
	t.Helper()
	verified, nonce := integrationClaimVerifiedWithNonce(ctx, t, store, suffix, 0)
	claim, err := oidcauth.NewClaimService(oidcauth.ClaimOptions{RequestTimeout: 10 * time.Second, RollbackTimeout: 2 * time.Second}, oidcauth.ClaimDependencies{Transactions: store, IDs: oidcauth.SystemClaimIDs{}, Clock: oidcauth.SystemStartClock{}})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := claim.ClaimBrowser(ctx, verified)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := (oidcauth.SystemClaimIDs{}).NewClaimIDs()
	if err != nil {
		t.Fatal(err)
	}
	command, err := oidcauth.NewFailureCommand(receipt, ids)
	if err != nil {
		t.Fatal(err)
	}
	// This only reads original immutable fixture metadata; it never starts failure.
	route := command.Snapshot().Route()
	template := integrationAuthTransactionPending(t, integrationAuthRouteParams{providerGeneration: 1, recoveryEpoch: 1, workspacePublicID: route.WorkspaceID().String()}, [4]string{
		"01890f00-0000-7000-8000-000000000fa3", "01890f01-0000-7000-8000-000000000fa3", "01890f02-0000-7000-8000-000000000fa3", "01890f03-0000-7000-8000-000000000fa3",
	})
	deps := integrationAuthStartDependencies(t, template, store, &integrationAuthStartTransactions{store: store})
	service, err := oidcauth.NewExchangeService(oidcauth.ExchangeOptions{RequestTimeout: 10 * time.Second, MaxConcurrent: 1}, oidcauth.ExchangeDependencies{
		Provider: integrationSubjectProvider{nonce: nonce, profile: profile}, Cipher: deps.VerifierCipher, DigestKey: deps.DigestKey, Clock: oidcauth.SystemStartClock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	code, err := oidcauth.ParseCode("synthetic-subject-code")
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := service.ExchangeBrowser(ctx, receipt, code)
	if err != nil {
		t.Fatal(err)
	}
	return exchange, route
}

// Controlled trusted-port evidence, not live-provider signature evidence.
type integrationSubjectProfile struct {
	authTime bool
	sid, acr string
	amr      []string
}
type integrationSubjectProvider struct {
	nonce   oidcauth.Nonce
	profile integrationSubjectProfile
}

func (provider integrationSubjectProvider) Authenticate(_ context.Context, request oidcauth.ExchangeRequest) (oidcauth.TokenEvidence, error) {
	now := time.Now().UTC().Truncate(time.Second)
	var authTime time.Time
	if provider.profile.authTime {
		authTime = now.Add(-time.Minute)
	}
	return oidcauth.NewTokenEvidence(oidcauth.TokenEvidenceParams{
		Issuer: request.Route().Issuer(), Subject: " Exact-é ", Nonce: provider.nonce, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute),
		AuthTime: authTime, SessionID: provider.profile.sid, ACR: provider.profile.acr, AMR: provider.profile.amr,
	})
}

func integrationSubjectKey(t *testing.T, value string, fill byte) oidcauth.SubjectKey {
	t.Helper()
	id, err := oidcauth.NewDigestKeyID(value)
	if err != nil {
		t.Fatal(err)
	}
	key, err := oidcauth.NewSubjectKey(id, integrationFilledBytes(fill, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func seedLoginSubjectFixture(ctx context.Context, t *testing.T, admin *pgx.Conn, digest oidcauth.SubjectDigest, membership bool) {
	t.Helper()
	suffix, kind := "fa0", "identity_subject"
	if membership {
		suffix, kind = "fa1", "workspace_membership"
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: "01890f01-0000-7000-8000-000000000" + suffix, eventPublicID: "01890f02-0000-7000-8000-000000000" + suffix, outboxPublicID: "01890f03-0000-7000-8000-000000000" + suffix,
		streamID: 1, aggregateKind: kind, aggregatePublicID: "01890f00-0000-7000-8000-000000000" + suffix, aggregateVersion: 1,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011", action: kind + ".created", permission: "system.bootstrap", outboxEventClass: kind + ".created",
	}, func(transaction pgx.Tx) {
		if membership {
			_, err := transaction.Exec(ctx, `INSERT INTO mesh.workspace_membership (
    public_id,deployment_id,workspace_id,principal_id,state,authority_generation,valid_from
) VALUES ('01890f00-0000-7000-8000-000000000fa1',1,101,11,'active',1,pg_catalog.transaction_timestamp()-INTERVAL '1 minute')`)
			if err != nil {
				t.Fatal(err)
			}
			return
		}
		value := digest.Bytes()
		_, err := transaction.Exec(ctx, `INSERT INTO mesh.identity_subject (
    public_id,deployment_id,identity_provider_id,principal_id,
    subject_digest_algorithm,subject_digest_key_id,subject_digest,claims_revision,last_seen_at,state
) VALUES ('01890f00-0000-7000-8000-000000000fa0',1,601,11,$1,$2,$3,1,pg_catalog.transaction_timestamp(),'active')`, digest.Algorithm(), digest.KeyID().String(), value[:])
		if err != nil {
			t.Fatal(err)
		}
	})
}

func integrationSubjectArguments(query oidcauth.SubjectLookup) []any {
	route := query.Snapshot().Route()
	args := integrationLoginRouteArguments(route)
	hash := query.Snapshot().SemanticHash()
	digests := query.Digests()
	active, previous := digests[0].Bytes(), digests[1].Bytes()
	return append(args, query.Claimed().TransactionID().String(), query.Claimed().Version(), hash[:], query.Claimed().ConsumedAt(), route.RedirectID(), route.ReturnRouteID(), digests[0].Algorithm(), digests[0].KeyID().String(), active[:], digests[1].KeyID().String(), previous[:])
}

func assertLoginSubjectArguments(ctx context.Context, t *testing.T, runtime *pgx.Conn, query oidcauth.SubjectLookup) {
	t.Helper()
	args := integrationSubjectArguments(query)
	for index, value := range args {
		t.Run("subject argument "+subjectArgumentName(index), func(t *testing.T) {
			tx, err := runtime.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackIntegrationTransaction(ctx, t, tx)
			if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.requested_workspace_public_id','01890f00-0000-7000-8000-000000000103',TRUE)`); err != nil {
				t.Fatal(err)
			}
			candidate := slices.Clone(args)
			switch typed := value.(type) {
			case string:
				if strings.Contains(typed, "01890f") {
					candidate[index] = "01890f00-0000-7000-8000-000000000fff"
				} else {
					candidate[index] = typed + "-wrong"
				}
			case int64:
				candidate[index] = typed + 1
			case []byte:
				candidate[index] = integrationFilledBytes(0x7f, 32)
			case []string:
				candidate[index] = []string{"wrong"}
			case time.Time:
				candidate[index] = typed.Add(time.Microsecond)
			default:
				t.Fatal("unhandled subject argument")
			}
			expected := int64(0)
			// The previous row still resolves when only the unused active candidate
			// changes. Conversely the absent active row cannot hide previous drift.
			if index == 23 || index == 24 {
				expected = 1
			}
			assertSubjectCount(ctx, t, tx, candidate, expected)
		})
	}
	for _, candidate := range []struct {
		name     string
		key      any
		digest   any
		expected int64
	}{
		{name: "no previous", expected: 0},
		{name: "half previous", key: args[25], expected: 0},
		{name: "same key id", key: args[23], digest: args[26], expected: 0},
		{name: "zero previous", key: args[25], digest: make([]byte, 32), expected: 0},
		{name: "oversize key", key: strings.Repeat("x", 129), digest: args[26], expected: 0},
	} {
		t.Run("subject "+candidate.name, func(t *testing.T) {
			tx, err := runtime.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackIntegrationTransaction(ctx, t, tx)
			probe := slices.Clone(args)
			probe[25], probe[26] = candidate.key, candidate.digest
			assertSubjectCount(ctx, t, tx, probe, candidate.expected)
		})
	}
}

func subjectArgumentName(index int) string {
	return []string{"deployment", "workspace", "provider", "client", "provider generation", "recovery epoch", "issuer", "discovery", "authorization", "token", "JWKS", "client identifier", "auth method", "scopes", "algorithms", "callback", "transaction", "claim version", "binding", "claim time", "redirect label", "return label", "subject algorithm", "active key", "active digest", "previous key", "previous digest"}[index]
}

func assertSubjectCount(ctx context.Context, t *testing.T, tx pgx.Tx, args []any, expected int64) {
	t.Helper()
	var count int64
	if err := tx.QueryRow(ctx, integrationSubjectCountSQL, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != expected {
		t.Fatalf("subject match count %d, want %d", count, expected)
	}
	assertAdmissionScopeCleared(ctx, t, tx)
}

func assertLoginSubjectRevocation(ctx context.Context, t *testing.T, admin *pgx.Conn, query oidcauth.SubjectLookup) {
	t.Helper()
	for _, candidate := range []struct{ name, query string }{
		{name: "provider suspended", query: "UPDATE mesh.identity_provider SET state='suspended' WHERE id=601"},
		{name: "workspace suspended", query: "UPDATE mesh.workspace SET state='suspended' WHERE id=101"},
		{name: "deployment quarantine", query: "UPDATE mesh.deployment SET recovery_state='quarantined' WHERE id=1"},
		{name: "account quarantine", query: "UPDATE mesh.account SET recovery_state='quarantined',session_generation=session_generation+1 WHERE id=701"},
		{name: "subject unlinked", query: "UPDATE mesh.identity_subject SET state='unlinked' WHERE public_id='01890f00-0000-7000-8000-000000000fa0'"},
		{name: "membership revoked", query: "UPDATE mesh.workspace_membership SET state='revoked',authority_generation=authority_generation+1 WHERE public_id='01890f00-0000-7000-8000-000000000fa1'"},
		{name: "membership expired", query: "UPDATE mesh.workspace_membership SET expires_at=pg_catalog.clock_timestamp()-INTERVAL '1 second',authority_generation=authority_generation+1 WHERE public_id='01890f00-0000-7000-8000-000000000fa1'"},
		{name: "membership not yet valid", query: "UPDATE mesh.workspace_membership SET valid_from=pg_catalog.clock_timestamp()+INTERVAL '1 minute',authority_generation=authority_generation+1 WHERE public_id='01890f00-0000-7000-8000-000000000fa1'"},
		{name: "routing suspended", query: "UPDATE mesh.workspace_identity_provider SET state='suspended' WHERE id=631"},
	} {
		t.Run("subject durable "+candidate.name, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackIntegrationTransaction(ctx, t, tx)
			setIntegrationChange(ctx, t, tx, "01890f01-0000-7000-8000-000000000fa4")
			// Fixed rollback-only synthetic manifest, never caller-controlled SQL.
			statement := strings.Replace(candidate.query, " WHERE ", ",version=version+1,updated_at=GREATEST(pg_catalog.transaction_timestamp(),updated_at) WHERE ", 1)
			if _, err := tx.Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
			assertSubjectCount(ctx, t, tx, integrationSubjectArguments(query), 0)
		})
	}
}

func assertLoginSubjectAmbiguity(ctx context.Context, t *testing.T, admin *pgx.Conn, query oidcauth.SubjectLookup) {
	t.Helper()
	for _, state := range []string{"active", "unlinked"} {
		t.Run("subject duplicate "+state, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackIntegrationTransaction(ctx, t, tx)
			setIntegrationChange(ctx, t, tx, "01890f01-0000-7000-8000-000000000fa5")
			digest := query.Digests()[0]
			value := digest.Bytes()
			_, err = tx.Exec(ctx, `INSERT INTO mesh.identity_subject (
    public_id,deployment_id,identity_provider_id,principal_id,
    subject_digest_algorithm,subject_digest_key_id,subject_digest,claims_revision,last_seen_at,state
) VALUES ('01890f00-0000-7000-8000-000000000fa5',1,601,11,$1,$2,$3,1,pg_catalog.transaction_timestamp(),$4)`, digest.Algorithm(), digest.KeyID().String(), value[:], state)
			if err != nil {
				t.Fatal(err)
			}
			assertSubjectCount(ctx, t, tx, integrationSubjectArguments(query), 0)
		})
	}
}

func assertLoginSubjectPrivileges(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var hardened, runtimeAllowed, workerAllowed, observerAllowed, publicAllowed, tableAllowed bool
	err := admin.QueryRow(ctx, `SELECT
    function.prosecdef AND NOT owner.rolsuper AND NOT owner.rolbypassrls
      AND owner.rolname='mesh_migrator' AND function.provolatile='v' AND function.proparallel='u'
      AND function.proconfig @> ARRAY['search_path=pg_catalog, mesh, mesh_ops']::TEXT[],
    pg_catalog.has_function_privilege('mesh_runtime',function.oid,'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_worker',function.oid,'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_observer',function.oid,'EXECUTE'),
    EXISTS (SELECT 1 FROM pg_catalog.aclexplode(function.proacl) AS acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE'),
    pg_catalog.has_table_privilege('mesh_runtime','mesh.identity_subject','SELECT')
      OR pg_catalog.has_table_privilege('mesh_runtime','mesh.workspace_membership','SELECT')
      OR pg_catalog.has_table_privilege('mesh_runtime','mesh.account','SELECT')
FROM pg_catalog.pg_proc AS function
JOIN pg_catalog.pg_namespace AS schema ON schema.oid=function.pronamespace
JOIN pg_catalog.pg_roles AS owner ON owner.oid=function.proowner
WHERE schema.nspname='mesh_ops' AND function.proname='resolve_oidc_login_subject_v1'`).Scan(&hardened, &runtimeAllowed, &workerAllowed, &observerAllowed, &publicAllowed, &tableAllowed)
	if err != nil {
		t.Fatal(err)
	}
	if !hardened || !runtimeAllowed || workerAllowed || observerAllowed || publicAllowed || tableAllowed {
		t.Fatal("subject function widened privileges")
	}
}

func assertLoginSubjectLiveClockAndTerminalClaim(ctx context.Context, t *testing.T, admin *pgx.Conn, query oidcauth.SubjectLookup) {
	t.Helper()
	for _, name := range []string{"live clock past frozen Begin", "terminal claim"} {
		t.Run("subject "+name, func(t *testing.T) {
			tx, err := admin.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackIntegrationTransaction(ctx, t, tx)
			if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('statement_timeout','1000ms',TRUE)`); err != nil {
				t.Fatal(err)
			}
			args := integrationSubjectArguments(query)
			setIntegrationChange(ctx, t, tx, "01890f01-0000-7000-8000-000000000fa6")
			if name == "terminal claim" {
				failureArgs := append(slices.Clone(args[:6]), args[16:20]...)
				var count int64
				if err := tx.QueryRow(ctx, integrationFailureCountSQL, failureArgs...).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 1 {
					t.Fatal("rollback-only terminal fixture failed")
				}
			} else {
				if _, err := tx.Exec(ctx, `UPDATE mesh.workspace_membership SET
    expires_at=pg_catalog.transaction_timestamp()+INTERVAL '20 milliseconds',
    version=version+1,authority_generation=authority_generation+1,
    updated_at=GREATEST(pg_catalog.transaction_timestamp(),updated_at)
WHERE public_id='01890f00-0000-7000-8000-000000000fa1'`); err != nil {
					t.Fatal(err)
				}
				// A bounded database-clock test, not polling for asynchronous state:
				// deliberately cross expiry while transaction_timestamp stays frozen.
				if _, err := tx.Exec(ctx, `SELECT pg_catalog.pg_sleep_until(pg_catalog.transaction_timestamp()+INTERVAL '25 milliseconds')`); err != nil {
					t.Fatal(err)
				}
				var pastLiveButNotFrozen bool
				if err := tx.QueryRow(ctx, `SELECT pg_catalog.clock_timestamp()>=expires_at
    AND pg_catalog.transaction_timestamp()<expires_at
FROM mesh.workspace_membership WHERE public_id='01890f00-0000-7000-8000-000000000fa1'`).Scan(&pastLiveButNotFrozen); err != nil {
					t.Fatal(err)
				}
				if !pastLiveButNotFrozen {
					t.Fatal("database clock fixture did not separate live/frozen time")
				}
			}
			assertSubjectCount(ctx, t, tx, args, 0)
		})
	}
}

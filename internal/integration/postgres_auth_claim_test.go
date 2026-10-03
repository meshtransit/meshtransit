//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

func assertPostgreSQLBrowserClaim(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn, pool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewAuthTransactionStore(pool, postgresadapter.AuthTransactionOptions{StatementTimeout: 5 * time.Second, LockTimeout: time.Second, IdleTimeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	assertBrowserClaimPrivileges(ctx, t, admin)
	for _, name := range []string{"concurrent callbacks", "committed lost ACK"} {
		t.Run("browser claim "+name, func(t *testing.T) {
			suffix := "970"
			if name == "committed lost ACK" {
				suffix = "971"
			}
			verified := integrationClaimVerified(ctx, t, store, suffix)
			before := authAdmissionAuthorityCounts(ctx, t, admin)
			var owners [2]*integrationClaimTransactions
			var results [2]oidcauth.ClaimResult
			var failures [2]error
			gate := make(chan struct{})
			var tasks sync.WaitGroup
			participants := 2
			if name == "committed lost ACK" {
				participants = 1
			}
			for index := range owners {
				if index >= participants {
					break
				}
				owners[index] = &integrationClaimTransactions{store: store, unknown: name == "committed lost ACK"}
				service, err := oidcauth.NewClaimService(oidcauth.ClaimOptions{RequestTimeout: 10 * time.Second, RollbackTimeout: 2 * time.Second}, oidcauth.ClaimDependencies{Transactions: owners[index], IDs: oidcauth.SystemClaimIDs{}, Clock: oidcauth.SystemStartClock{}})
				if err != nil {
					t.Fatal(err)
				}
				tasks.Go(func() { <-gate; results[index], failures[index] = service.ClaimBrowser(ctx, verified) })
			}
			close(gate)
			tasks.Wait()
			winners, committed := 0, 0
			var winningCommand oidcauth.ClaimCommand
			for index := range results {
				if index >= participants {
					break
				}
				if results[index].IsValid() {
					winners++
					if failures[index] != nil {
						t.Fatal("receipt with error")
					}
				}
				if owners[index].commits == 1 {
					committed++
					winningCommand = owners[index].command
				}
			}
			if committed != 1 || (name == "concurrent callbacks" && winners != 1) || (name == "committed lost ACK" && (winners != 0 || !errors.Is(failures[0], oidcauth.ErrCommitOutcomeUnknown))) {
				t.Fatal("claim was duplicated or uncertain receipt released")
			}
			assertBrowserClaimEvidence(ctx, t, admin, winningCommand)
			if after := authAdmissionAuthorityCounts(ctx, t, admin); after[0] != before[0] || after[1] != before[1]+1 || after[2] != before[2]+1 || after[3] != before[3]+1 || after[4] != before[4] {
				t.Fatalf("claim authority counts before=%v after=%v", before, after)
			}
			// Even after real durable Commit with its ACK hidden, possession alone
			// cannot reconstruct a receipt or consume/retry the transaction again.
			retryOwner := &integrationClaimTransactions{store: store}
			retry, err := oidcauth.NewClaimService(oidcauth.ClaimOptions{RequestTimeout: 10 * time.Second, RollbackTimeout: 2 * time.Second}, oidcauth.ClaimDependencies{Transactions: retryOwner, IDs: oidcauth.SystemClaimIDs{}, Clock: oidcauth.SystemStartClock{}})
			if err != nil {
				t.Fatal(err)
			}
			if result, err := retry.ClaimBrowser(ctx, verified); err == nil || result.IsValid() || retryOwner.commits != 0 {
				t.Fatal("consuming evidence was reclaimed")
			}
		})
	}
	t.Run("browser claim revoked after proof", func(t *testing.T) {
		verified := integrationClaimVerified(ctx, t, store, "972")
		setAdmissionFixtureProviderState(ctx, t, admin, "suspended", 4, "973")
		defer setAdmissionFixtureProviderState(ctx, t, admin, "active", 5, "974")
		before := authAdmissionAuthorityCounts(ctx, t, admin)
		owner := &integrationClaimTransactions{store: store}
		service, err := oidcauth.NewClaimService(oidcauth.ClaimOptions{RequestTimeout: 10 * time.Second, RollbackTimeout: 2 * time.Second}, oidcauth.ClaimDependencies{Transactions: owner, IDs: oidcauth.SystemClaimIDs{}, Clock: oidcauth.SystemStartClock{}})
		if err != nil {
			t.Fatal(err)
		}
		if result, err := service.ClaimBrowser(ctx, verified); err == nil || result.IsValid() || owner.commits != 0 {
			t.Fatal("stale proof bypassed revoked authority")
		}
		if after := authAdmissionAuthorityCounts(ctx, t, admin); after != before {
			t.Fatal("rejected claim committed evidence")
		}
	})
	verified := integrationClaimVerified(ctx, t, store, "975")
	assertBrowserClaimScopeAndCAS(ctx, t, runtime, verified)
}

func integrationClaimVerified(ctx context.Context, t *testing.T, store *postgresadapter.AuthTransactionStore, suffix string) oidcauth.VerifiedBrowser {
	t.Helper()
	return integrationClaimVerifiedRemaining(ctx, t, store, suffix, 0)
}

func integrationClaimVerifiedRemaining(ctx context.Context, t *testing.T, store *postgresadapter.AuthTransactionStore, suffix string, remaining time.Duration) oidcauth.VerifiedBrowser {
	t.Helper()
	verified, _ := integrationClaimVerifiedWithNonce(ctx, t, store, suffix, remaining)
	return verified
}

func integrationClaimVerifiedWithNonce(ctx context.Context, t *testing.T, store *postgresadapter.AuthTransactionStore, suffix string, remaining time.Duration) (oidcauth.VerifiedBrowser, oidcauth.Nonce) {
	t.Helper()
	template := integrationAuthTransactionPending(t, integrationAuthRouteParams{providerGeneration: 1, recoveryEpoch: 1, workspacePublicID: "01890f00-0000-7000-8000-000000000101"}, [4]string{
		"01890f00-0000-7000-8000-000000000" + suffix, "01890f01-0000-7000-8000-000000000" + suffix,
		"01890f02-0000-7000-8000-000000000" + suffix, "01890f03-0000-7000-8000-000000000" + suffix,
	})
	transactions := &integrationAuthStartTransactions{store: store}
	dependencies := integrationAuthStartDependencies(t, template, store, transactions)
	lifetime := 5 * time.Minute
	if remaining > 0 {
		lifetime = time.Minute
		clock := integrationFailureStartClock{time.Now().UTC().Add(-time.Minute + remaining)}
		dependencies.Clock, dependencies.CreationClock = clock, clock
	}
	start, err := oidcauth.NewStartService(oidcauth.StartOptions{RequestTimeout: 10 * time.Second, PendingLifetime: lifetime, RollbackTimeout: 2 * time.Second, ResolveTimeout: 2 * time.Second}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	started, err := start.Start(ctx, template.Route())
	if err != nil {
		t.Fatal(err)
	}
	location, err := url.Parse(started.AuthorizationRequest().Location())
	if err != nil {
		t.Fatal("invalid synthetic authorization URL")
	}
	state, err := oidcauth.ParseState(location.Query().Get("state"))
	if err != nil {
		t.Fatal("invalid synthetic state")
	}
	nonce, err := oidcauth.ParseNonce(location.Query().Get("nonce"))
	if err != nil {
		t.Fatal("invalid synthetic nonce")
	}
	verify, err := oidcauth.NewBrowserVerificationService(oidcauth.BrowserVerificationOptions{RequestTimeout: 10 * time.Second}, oidcauth.BrowserVerificationDependencies{Pending: store, DigestKey: dependencies.DigestKey, VerifierCipher: dependencies.VerifierCipher, Clock: oidcauth.SystemStartClock{}})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verify.VerifyBrowser(ctx, template.Route(), state, started.PreAuthCookie())
	if err != nil {
		digest, digestErr := dependencies.DigestKey.State(
			template.Route().DeploymentID(), template.Route().RecoveryEpoch(), state,
		)
		if digestErr != nil {
			t.Fatalf("durable browser verification error=%v; diagnostic digest failed", err)
		}
		snapshot, found, loadErr := store.LoadPending(ctx, template.Route(), digest)
		binding, bindingErr := template.Route().Binding(snapshot.TransactionID())
		proof, proofErr := dependencies.VerifierCipher.OpenBrowser(binding, snapshot.VerifierCiphertext())
		cookieMatch := bindingErr == nil && proofErr == nil && dependencies.DigestKey.VerifyPreAuthCookie(binding, started.PreAuthCookie(), proof.CookieDigest())
		now := time.Now().UTC()
		t.Logf("browser diagnostic: binding_ok=%t proof_ok=%t cookie_ok=%t created_not_future=%t", bindingErr == nil, proofErr == nil, cookieMatch, !now.Before(snapshot.CreatedAt()))
		t.Fatalf(
			"durable browser verification error=%v; found=%t load_failed=%t route_match=%t "+
				"created_offset=%s expiry_remaining=%s",
			err,
			found,
			loadErr != nil,
			snapshot.MatchesRoute(template.Route()),
			snapshot.CreatedAt().Sub(now),
			snapshot.ExpiresAt().Sub(now),
		)
	}
	return verified, nonce
}

func assertBrowserClaimEvidence(ctx context.Context, t *testing.T, admin *pgx.Conn, command oidcauth.ClaimCommand) {
	t.Helper()
	snapshot := command.Snapshot()
	var state, action, eventClass, operation string
	var version, beforeVersion, afterVersion, aggregateVersion int64
	var consumedAt time.Time
	var hash, ciphertext, beforeHash, afterHash []byte
	var noActor, noNetwork, noResult bool
	if err := admin.QueryRow(ctx, `SELECT auth.state, auth.version, auth.consumed_at, auth.binding_semantic_hash,
    auth.pkce_verifier_ciphertext, audit.action, audit.before_semantic_hash, audit.after_semantic_hash,
    audit.actor_principal_public_id IS NULL, outbox.event_class, outbox.aggregate_version,
    outbox.network_revision IS NULL AND audit.network_id IS NULL,
    auth.principal_id IS NULL AND auth.consumed_result_kind IS NULL AND auth.failure_class IS NULL,
    mutation.operation, mutation.before_version, mutation.after_version
FROM mesh.auth_transaction AS auth
JOIN mesh_audit.authority_mutation AS mutation ON mutation.row_public_id=auth.public_id
    AND mutation.aggregate_kind='auth_transaction' AND mutation.change_public_id=$2::UUID
JOIN mesh_audit.audit_event_identity AS identity ON identity.change_public_id=mutation.change_public_id AND identity.transaction_id=mutation.transaction_id
JOIN mesh_audit.audit_event AS audit ON audit.event_identity_id=identity.id AND audit.occurred_at=identity.occurred_at
    AND audit.target_kind='auth_transaction' AND audit.target_public_id=auth.public_id
JOIN mesh_ops.outbox_event AS outbox ON outbox.change_public_id=mutation.change_public_id AND outbox.transaction_id=mutation.transaction_id
    AND outbox.aggregate_kind='auth_transaction' AND outbox.aggregate_public_id=auth.public_id
WHERE auth.public_id=$1::UUID`, snapshot.TransactionID().String(), command.MutationIDs().ChangeID().String()).Scan(
		&state, &version, &consumedAt, &hash, &ciphertext, &action, &beforeHash, &afterHash, &noActor, &eventClass, &aggregateVersion, &noNetwork, &noResult, &operation, &beforeVersion, &afterVersion,
	); err != nil {
		t.Fatal(err)
	}
	claimed, err := oidcauth.NewClaimed(snapshot, version, consumedAt)
	if err != nil {
		t.Fatal(err)
	}
	binding, before, after := snapshot.SemanticHash(), claimed.BeforeSemanticHash(), claimed.AfterSemanticHash()
	if state != "consuming" || version != 2 || action != "auth_transaction.claimed" || eventClass != "identity.auth_transaction.claimed" || aggregateVersion != 2 || operation != "update" || beforeVersion != 1 || afterVersion != 2 || !noActor || !noNetwork || !noResult || !bytes.Equal(hash, binding[:]) || !bytes.Equal(ciphertext, snapshot.VerifierCiphertext().Bytes()) || !bytes.Equal(beforeHash, before[:]) || !bytes.Equal(afterHash, after[:]) {
		t.Fatal("durable claim evidence mismatched lifecycle/binding/PKCE/authority")
	}
}

func assertBrowserClaimPrivileges(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var hardened, runtimeAllowed, workerAllowed, observerAllowed, tableAllowed bool
	if err := admin.QueryRow(ctx, `SELECT function.prosecdef AND NOT owner.rolsuper AND NOT owner.rolbypassrls
    AND owner.rolname='mesh_migrator' AND function.proconfig @> ARRAY['search_path=pg_catalog, mesh, mesh_ops']::TEXT[],
    pg_catalog.has_function_privilege('mesh_runtime', function.oid, 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_worker', function.oid, 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_observer', function.oid, 'EXECUTE'),
    pg_catalog.has_table_privilege('mesh_runtime', 'mesh.auth_transaction', 'SELECT') OR pg_catalog.has_table_privilege('mesh_runtime', 'mesh.auth_transaction', 'UPDATE')
FROM pg_catalog.pg_proc AS function JOIN pg_catalog.pg_namespace AS schema ON schema.oid=function.pronamespace
JOIN pg_catalog.pg_roles AS owner ON owner.oid=function.proowner
WHERE schema.nspname='mesh_ops' AND function.proname='claim_oidc_browser_v1'`).Scan(&hardened, &runtimeAllowed, &workerAllowed, &observerAllowed, &tableAllowed); err != nil {
		t.Fatal(err)
	}
	if !hardened || !runtimeAllowed || workerAllowed || observerAllowed || tableAllowed {
		t.Fatal("claim privileges widened")
	}
}

func assertBrowserClaimScopeAndCAS(ctx context.Context, t *testing.T, runtime *pgx.Conn, verified oidcauth.VerifiedBrowser) {
	t.Helper()
	snapshot := verified.Snapshot()
	digest, hash := snapshot.StateDigest().Bytes(), snapshot.SemanticHash()
	args := append(integrationLoginRouteArguments(snapshot.Route()), snapshot.StateDigest().Algorithm(), snapshot.StateDigest().KeyID().String(), digest[:], snapshot.Route().RedirectID(), snapshot.Route().ReturnRouteID(), snapshot.TransactionID().String(), snapshot.Version(), hash[:])
	const countSQL = `SELECT pg_catalog.count(*) FROM mesh_ops.claim_oidc_browser_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::TEXT,$8::TEXT,$9::TEXT,$10::TEXT,$11::TEXT,$12::TEXT,
    $13::TEXT,$14::TEXT[],$15::TEXT[],$16::TEXT,$17::TEXT,$18::TEXT,$19::BYTEA,$20::TEXT,$21::TEXT,$22::UUID,$23::BIGINT,$24::BYTEA)`
	for _, candidate := range []struct {
		name  string
		index int
		value any
	}{
		{"workspace", 1, "01890f00-0000-7000-8000-000000000102"}, {"generation", 4, int64(2)}, {"epoch", 5, int64(2)},
		{"state", 18, make([]byte, 32)}, {"redirect label", 19, "other-callback"}, {"return label", 20, "other-return"},
		{"transaction", 21, "01890f00-0000-7000-8000-000000000966"}, {"version", 22, int64(2)}, {"hash", 23, make([]byte, 32)},
		{"valid rollback probe", -1, nil},
	} {
		t.Run("browser claim scope "+candidate.name, func(t *testing.T) {
			probe, err := runtime.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackIntegrationTransaction(ctx, t, probe)
			if _, err := probe.Exec(ctx, `SELECT pg_catalog.set_config('mesh.requested_workspace_public_id','01890f00-0000-7000-8000-000000000102',TRUE),
    pg_catalog.set_config('mesh.change_public_id','01890f01-0000-7000-8000-000000000976',TRUE)`); err != nil {
				t.Fatal(err)
			}
			changed := append([]any(nil), args...)
			if candidate.index >= 0 {
				changed[candidate.index] = candidate.value
			}
			var count int
			if err := probe.QueryRow(ctx, countSQL, changed...).Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 0
			if candidate.index < 0 {
				want = 1
			}
			if count != want {
				t.Fatal("claim did not enforce exact scope/CAS")
			}
			assertAdmissionScopeCleared(ctx, t, probe)
		})
	}
	t.Run("browser claim cannot commit without audit and outbox", func(t *testing.T) {
		probe, err := runtime.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackIntegrationTransaction(ctx, t, probe)
		if _, err := probe.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id','01890f01-0000-7000-8000-000000000977',TRUE)`); err != nil {
			t.Fatal("failed setup of missing-evidence probe")
		}
		var count int
		if err := probe.QueryRow(ctx, countSQL, args...).Scan(&count); err != nil || count != 1 {
			t.Fatal("missing-evidence probe did not claim")
		}
		assertAdmissionScopeCleared(ctx, t, probe)
		if err := probe.Commit(ctx); err == nil {
			t.Fatal("unaudited consuming write committed")
		}
		// Deferred coverage must roll back the entire claim, not strand consuming
		// state when the mandatory evidence append is omitted.
		if err := runtime.QueryRow(ctx, integrationPendingBrowserCountSQL, args[:21]...).Scan(&count); err != nil || count != 1 {
			t.Fatal("missing evidence did not atomically roll back consumption")
		}
	})
}

type integrationClaimTransactions struct {
	store   *postgresadapter.AuthTransactionStore
	command oidcauth.ClaimCommand
	unknown bool
	commits int
}

func (owner *integrationClaimTransactions) BeginClaim(ctx context.Context, route oidcauth.Route) (oidcauth.ClaimTransaction, error) {
	unit, err := owner.store.BeginClaim(ctx, route)
	if err != nil {
		return unit, err
	}
	return &integrationClaimTransaction{unit: unit, owner: owner}, nil
}

type integrationClaimTransaction struct {
	unit  oidcauth.ClaimTransaction
	owner *integrationClaimTransactions
}

func (unit *integrationClaimTransaction) Claim(ctx context.Context, command oidcauth.ClaimCommand) (oidcauth.Claimed, error) {
	unit.owner.command = command
	return unit.unit.Claim(ctx, command)
}
func (unit *integrationClaimTransaction) Commit(ctx context.Context) error {
	unit.owner.commits++
	if err := unit.unit.Commit(ctx); err != nil {
		return err
	}
	if unit.owner.unknown {
		return oidcauth.ErrCommitOutcomeUnknown
	}
	return nil
}
func (unit *integrationClaimTransaction) Rollback(ctx context.Context) error {
	return unit.unit.Rollback(ctx)
}

//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

const integrationFailureCountSQL = `SELECT pg_catalog.count(*) FROM mesh_ops.fail_oidc_browser_v2(
    $1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::UUID,$7::BIGINT,$8::BYTEA,$9::TIMESTAMPTZ)`

// integrationFailureV1CountSQL is the retained rollback-era terminal function,
// used only as a control proving a Workspace-scoped copy is otherwise terminable.
const integrationFailureV1CountSQL = `SELECT pg_catalog.count(*) FROM mesh_ops.fail_oidc_browser_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::UUID,$8::BIGINT,$9::BYTEA,$10::TIMESTAMPTZ)`

func assertPostgreSQLBrowserFailure(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn, pool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewAuthTransactionStore(pool, postgresadapter.AuthTransactionOptions{StatementTimeout: 10 * time.Second, LockTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	assertBrowserFailurePrivileges(ctx, t, admin)
	receipt := integrationFailureReceipt(ctx, t, store, "f80", 0)
	assertBrowserFailureScopeAndCoverage(ctx, t, admin, runtime, receipt)
	for _, name := range []string{"confirmed", "lost ACK", "revoked provider"} {
		t.Run("browser failure "+name, func(t *testing.T) {
			suffix := "f81"
			if name == "lost ACK" {
				suffix = "f82"
			}
			if name == "revoked provider" {
				suffix = "f83"
			}
			receipt := integrationFailureReceipt(ctx, t, store, suffix, 0)
			if name == "revoked provider" {
				setAdmissionFixtureProviderState(ctx, t, admin, "suspended", 6, "f84")
				defer setAdmissionFixtureProviderState(ctx, t, admin, "active", 7, "f85")
			}
			before := authAdmissionAuthorityCounts(ctx, t, admin)
			owner := &integrationFailureTransactions{store: store, unknown: name == "lost ACK"}
			service := integrationFailureService(t, owner)
			result, err := service.FailBrowser(ctx, receipt)
			if name == "lost ACK" {
				if err == nil || !errors.Is(err, oidcauth.ErrCommitOutcomeUnknown) || result.IsValid() {
					t.Fatal("uncertain terminal released")
				}
			} else if err != nil || !result.IsValid() {
				t.Fatal(err)
			}
			if owner.commits != 1 {
				t.Fatal("terminal Commit count")
			}
			assertBrowserFailureEvidence(ctx, t, admin, owner.command)
			if after := authAdmissionAuthorityCounts(ctx, t, admin); after[0] != before[0] || after[1] != before[1]+1 || after[2] != before[2]+1 || after[3] != before[3]+1 || after[4] != before[4] {
				t.Fatal("terminal authority evidence counts")
			}
			if next, err := service.FailBrowser(ctx, receipt); err == nil || next.IsValid() || owner.commits != 1 {
				t.Fatal("terminal attempt retried")
			}
		})
	}
	t.Run("browser failure independent SQL contenders", func(t *testing.T) {
		receipt := integrationFailureReceipt(ctx, t, store, "f86", 0)
		var results [2]oidcauth.Terminated
		var failures [2]error
		var commands [2]oidcauth.FailureCommand
		gate := make(chan struct{})
		var tasks sync.WaitGroup
		for index := range results {
			ids, err := (oidcauth.SystemClaimIDs{}).NewClaimIDs()
			if err != nil {
				t.Fatal(err)
			}
			commands[index], err = oidcauth.NewFailureCommand(receipt, ids)
			if err != nil {
				t.Fatal(err)
			}
			tasks.Go(func() {
				<-gate
				unit, err := store.BeginFailure(ctx, commands[index].Snapshot().Route())
				if err != nil {
					failures[index] = err
					return
				}
				defer func() {
					cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
					defer cancel()
					failures[index] = errors.Join(failures[index], unit.Rollback(cleanup))
				}()
				results[index], failures[index] = unit.Fail(ctx, commands[index])
				if failures[index] == nil {
					failures[index] = unit.Commit(ctx)
				}
			})
		}
		close(gate)
		tasks.Wait()
		winners := 0
		for index := range results {
			if failures[index] == nil && results[index].IsValid() {
				winners++
				assertBrowserFailureEvidence(ctx, t, admin, commands[index])
			}
		}
		if winners != 1 {
			t.Fatal("terminal SQL CAS duplicated")
		}
	})
	assertBrowserFailureAuditWait(ctx, t, admin, store)
}

func integrationFailureReceipt(ctx context.Context, t *testing.T, store *postgresadapter.AuthTransactionStore, suffix string, remaining time.Duration) oidcauth.ClaimResult {
	t.Helper()
	verified := integrationClaimVerifiedRemaining(ctx, t, store, suffix, remaining)
	claim, err := oidcauth.NewClaimService(oidcauth.ClaimOptions{RequestTimeout: 10 * time.Second, RollbackTimeout: 2 * time.Second}, oidcauth.ClaimDependencies{Transactions: store, IDs: oidcauth.SystemClaimIDs{}, Clock: oidcauth.SystemStartClock{}})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := claim.ClaimBrowser(ctx, verified)
	if err != nil {
		t.Fatal(err)
	}
	return receipt
}
func integrationFailureService(t *testing.T, transactions oidcauth.FailureTransactions) *oidcauth.FailureService {
	t.Helper()
	service, err := oidcauth.NewFailureService(oidcauth.FailureOptions{RequestTimeout: 10 * time.Second, RollbackTimeout: 2 * time.Second}, oidcauth.FailureDependencies{Transactions: transactions, IDs: oidcauth.SystemClaimIDs{}, Clock: oidcauth.SystemStartClock{}})
	if err != nil {
		t.Fatal(err)
	}
	return service
}
func integrationFailureArguments(t *testing.T, receipt oidcauth.ClaimResult) []any {
	t.Helper()
	ids, err := (oidcauth.SystemClaimIDs{}).NewClaimIDs()
	if err != nil {
		t.Fatal(err)
	}
	command, err := oidcauth.NewFailureCommand(receipt, ids)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, route := command.Snapshot(), command.Snapshot().Route()
	hash := snapshot.SemanticHash()
	return []any{route.DeploymentID().String(), route.ProviderID().String(), route.ClientID().String(), route.ProviderGeneration(), route.RecoveryEpoch(), snapshot.TransactionID().String(), int64(2), hash[:], command.Claimed().ConsumedAt()}
}
func assertBrowserFailureScopeAndCoverage(ctx context.Context, t *testing.T, admin, runtime *pgx.Conn, receipt oidcauth.ClaimResult) {
	t.Helper()
	args := integrationFailureArguments(t, receipt)
	for _, candidate := range []struct {
		name  string
		index int
		value any
	}{
		{"deployment", 0, "01890f00-0000-7000-8000-000000000002"}, {"provider", 1, "01890f00-0000-7000-8000-000000000602"}, {"client", 2, "01890f00-0000-7000-8000-000000000622"}, {"generation", 3, int64(2)}, {"epoch", 4, int64(2)}, {"transaction", 5, "01890f00-0000-7000-8000-000000000966"}, {"version", 6, int64(3)}, {"hash", 7, make([]byte, 32)}, {"claim time", 8, receipt.Claimed().ConsumedAt().Add(time.Microsecond)}, {"null", 7, nil}, {"valid rollback", -1, nil},
	} {
		t.Run("browser failure scope "+candidate.name, func(t *testing.T) {
			probe, err := runtime.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackIntegrationTransaction(ctx, t, probe)
			if _, err := probe.Exec(ctx, `SELECT pg_catalog.set_config('mesh.requested_workspace_public_id','01890f00-0000-7000-8000-000000000102',TRUE), pg_catalog.set_config('mesh.change_public_id','01890f01-0000-7000-8000-000000000f88',TRUE)`); err != nil {
				t.Fatal(err)
			}
			changed := append([]any(nil), args...)
			if candidate.index >= 0 {
				changed[candidate.index] = candidate.value
			}
			var count int
			if err := probe.QueryRow(ctx, integrationFailureCountSQL, changed...).Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 0
			if candidate.index < 0 {
				want = 1
			}
			if count != want {
				t.Fatal("terminal exact scope/CAS")
			}
			assertAdmissionScopeCleared(ctx, t, probe)
		})
	}
	t.Run("browser failure missing evidence rolls back erasure", func(t *testing.T) {
		probe, err := runtime.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackIntegrationTransaction(ctx, t, probe)
		if _, err := probe.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id','01890f01-0000-7000-8000-000000000f89',TRUE)`); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := probe.QueryRow(ctx, integrationFailureCountSQL, args...).Scan(&count); err != nil || count != 1 {
			t.Fatal("terminal probe", err)
		}
		if err := probe.Commit(ctx); err == nil {
			t.Fatal("unaudited terminal committed")
		}
		if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.auth_transaction WHERE public_id=$1::UUID AND state='consuming' AND version=2 AND pkce_verifier_ciphertext IS NOT NULL`, args[5]).Scan(&count); err != nil || count != 1 {
			t.Fatal("erasure not atomic")
		}
	})
	t.Run("browser failure rejects Workspace-scoped v1 transaction", func(t *testing.T) {
		probe, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		// Rollback-only: a consuming v1 row (workspace_id NOT NULL) is not v2 scope.
		defer rollbackIntegrationTransaction(ctx, t, probe)
		if _, err := probe.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id','01890f01-0000-7000-8000-000000000f8c',TRUE)`); err != nil {
			t.Fatal(err)
		}
		const copyID = "01890f00-0000-7000-8000-000000000f8c"
		insertIntegrationWorkspaceScopedAuthCopy(ctx, t, probe, args[5].(string), copyID, integrationFilledBytes(0x8c, 32), true)
		scoped := append([]any(nil), args...)
		scoped[5] = copyID
		var count int
		if err := probe.QueryRow(ctx, integrationFailureCountSQL, scoped...).Scan(&count); err != nil || count != 0 {
			t.Fatalf("v2 failure of Workspace-scoped transaction count=%d err=%v, want none", count, err)
		}
		assertAdmissionScopeCleared(ctx, t, probe)
		legacy := append([]any{scoped[0], "01890f00-0000-7000-8000-000000000101"}, scoped[1:]...)
		if err := probe.QueryRow(ctx, integrationFailureV1CountSQL, legacy...).Scan(&count); err != nil || count != 1 {
			t.Fatalf("v1 control failure of Workspace-scoped copy count=%d err=%v, want 1", count, err)
		}
	})
	t.Run("browser failure revoked Workspace rollback probe", func(t *testing.T) {
		probe, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackIntegrationTransaction(ctx, t, probe)
		if _, err := probe.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id','01890f01-0000-7000-8000-000000000f8a',TRUE)`); err != nil {
			t.Fatal(err)
		}
		if _, err := probe.Exec(ctx, `UPDATE mesh.workspace SET state='suspended', version=version+1 WHERE id=101`); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := probe.QueryRow(ctx, integrationFailureCountSQL, args...).Scan(&count); err != nil || count != 1 {
			t.Fatal("revoked Workspace stranded proof", err)
		}
		assertAdmissionScopeCleared(ctx, t, probe)
	})
}

func assertBrowserFailureEvidence(ctx context.Context, t *testing.T, admin *pgx.Conn, command oidcauth.FailureCommand) {
	t.Helper()
	var state, class, action, eventClass string
	var at time.Time
	var hash, beforeHash, afterHash []byte
	var erased, noGrant, versions bool
	if err := admin.QueryRow(ctx, `SELECT auth.state,auth.failure_class,(audit.payload->>'terminated_at')::TIMESTAMPTZ,auth.binding_semantic_hash,audit.before_semantic_hash,audit.after_semantic_hash,
 auth.pkce_verifier_encryption_algorithm IS NULL AND auth.pkce_verifier_encryption_key_id IS NULL AND auth.pkce_verifier_ciphertext IS NULL,
 auth.principal_id IS NULL AND auth.consumed_result_kind IS NULL AND auth.consumed_result_public_id IS NULL AND audit.actor_principal_public_id IS NULL AND audit.network_id IS NULL AND outbox.network_revision IS NULL
   AND NOT (audit.payload ? 'workspace_public_id') AND NOT (outbox.payload ? 'workspace_public_id'),
 auth.version=3 AND mutation.before_version=2 AND mutation.after_version=3 AND outbox.aggregate_version=3,audit.action,outbox.event_class
 FROM mesh.auth_transaction AS auth
 JOIN mesh_audit.authority_mutation AS mutation ON mutation.row_public_id=auth.public_id AND mutation.aggregate_kind='auth_transaction' AND mutation.change_public_id=$2::UUID
 JOIN mesh_audit.audit_event_identity AS identity ON identity.change_public_id=mutation.change_public_id AND identity.transaction_id=mutation.transaction_id
 JOIN mesh_audit.audit_event AS audit ON audit.event_identity_id=identity.id AND audit.occurred_at=identity.occurred_at
 JOIN mesh_ops.outbox_event AS outbox ON outbox.change_public_id=mutation.change_public_id AND outbox.transaction_id=mutation.transaction_id
 WHERE auth.public_id=$1::UUID`, command.Snapshot().TransactionID().String(), command.MutationIDs().ChangeID().String()).Scan(&state, &class, &at, &hash, &beforeHash, &afterHash, &erased, &noGrant, &versions, &action, &eventClass); err != nil {
		t.Fatal(err)
	}
	terminal, err := oidcauth.NewTerminated(command.Claimed(), 3, state, class, at)
	if err != nil {
		t.Fatal(err)
	}
	binding, before, after := command.Snapshot().SemanticHash(), terminal.BeforeSemanticHash(), terminal.AfterSemanticHash()
	if !erased || !noGrant || !versions || action != "auth_transaction.terminated" || eventClass != "identity.auth_transaction.terminated" || !bytes.Equal(hash, binding[:]) || !bytes.Equal(beforeHash, before[:]) || !bytes.Equal(afterHash, after[:]) {
		t.Fatal("terminal durable evidence mismatch")
	}
}
func assertBrowserFailurePrivileges(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var hardened, runtimeAllowed, workerAllowed, observerAllowed, tableAllowed, publicAllowed bool
	if err := admin.QueryRow(ctx, `SELECT function.prosecdef AND owner.rolname='mesh_migrator' AND NOT owner.rolsuper AND NOT owner.rolbypassrls AND function.proconfig @> ARRAY['search_path=pg_catalog, mesh, mesh_ops']::TEXT[],
 pg_catalog.has_function_privilege('mesh_runtime',function.oid,'EXECUTE'),pg_catalog.has_function_privilege('mesh_worker',function.oid,'EXECUTE'),pg_catalog.has_function_privilege('mesh_observer',function.oid,'EXECUTE'),
 pg_catalog.has_table_privilege('mesh_runtime','mesh.auth_transaction','SELECT') OR pg_catalog.has_table_privilege('mesh_runtime','mesh.auth_transaction','UPDATE'),
 EXISTS(SELECT 1 FROM pg_catalog.aclexplode(function.proacl) AS acl WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE')
 FROM pg_catalog.pg_proc AS function JOIN pg_catalog.pg_namespace AS schema ON schema.oid=function.pronamespace JOIN pg_catalog.pg_roles AS owner ON owner.oid=function.proowner WHERE schema.nspname='mesh_ops' AND function.proname='fail_oidc_browser_v2'`).Scan(&hardened, &runtimeAllowed, &workerAllowed, &observerAllowed, &tableAllowed, &publicAllowed); err != nil {
		t.Fatal(err)
	}
	if !hardened || !runtimeAllowed || workerAllowed || observerAllowed || tableAllowed || publicAllowed {
		t.Fatal("terminal privilege widened")
	}
}

func assertBrowserFailureAuditWait(ctx context.Context, t *testing.T, admin *pgx.Conn, store *postgresadapter.AuthTransactionStore) {
	t.Helper()
	t.Run("browser failure expires during audit head wait", func(t *testing.T) {
		receipt := integrationFailureReceipt(ctx, t, store, "f8b", 3*time.Second)
		args := integrationFailureArguments(t, receipt)
		var expiresAt time.Time
		if err := admin.QueryRow(ctx, `SELECT expires_at FROM mesh.auth_transaction WHERE public_id=$1::UUID`, args[5]).Scan(&expiresAt); err != nil {
			t.Fatal(err)
		}
		held, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rollbackIntegrationTransaction(ctx, t, held)
		if _, err := held.Exec(ctx, `SELECT id FROM mesh_audit.audit_stream WHERE id=1 FOR UPDATE`); err != nil {
			t.Fatal(err)
		}
		owner := &integrationFailureTransactions{store: store}
		service := integrationFailureService(t, owner)
		type completion struct {
			result oidcauth.FailureResult
			err    error
		}
		finished := make(chan completion, 1)
		go func() { result, err := service.FailBrowser(ctx, receipt); finished <- completion{result, err} }()
		// Wait on a real clock, not frozen transaction_timestamp. Audit head is
		// held throughout; any early completion fails instead of silently passing.
		timer := time.NewTimer(time.Until(expiresAt) + 20*time.Millisecond)
		defer timer.Stop()
		select {
		case early := <-finished:
			t.Fatal("failure did not wait for audit lock", early.err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
		if err := held.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case done := <-finished:
			if done.err != nil || !done.result.IsValid() || done.result.Terminated().State() != "expired" {
				t.Fatal("deadline after audit lock not applied", done.err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		assertBrowserFailureEvidence(ctx, t, admin, owner.command)
	})
}

type integrationFailureStartClock struct{ at time.Time }

func (clock integrationFailureStartClock) CreationTime(ctx context.Context) (time.Time, error) {
	return clock.at, ctx.Err()
}

func (clock integrationFailureStartClock) Now() time.Time { return clock.at }

type integrationFailureTransactions struct {
	store   *postgresadapter.AuthTransactionStore
	unknown bool
	command oidcauth.FailureCommand
	commits int
}

func (owner *integrationFailureTransactions) BeginFailure(ctx context.Context, route oidcauth.Route) (oidcauth.FailureTransaction, error) {
	unit, err := owner.store.BeginFailure(ctx, route)
	if err != nil {
		return unit, err
	}
	return &integrationFailureTransaction{unit: unit, owner: owner}, nil
}

type integrationFailureTransaction struct {
	unit  oidcauth.FailureTransaction
	owner *integrationFailureTransactions
}

func (unit *integrationFailureTransaction) Fail(ctx context.Context, command oidcauth.FailureCommand) (oidcauth.Terminated, error) {
	unit.owner.command = command
	return unit.unit.Fail(ctx, command)
}
func (unit *integrationFailureTransaction) Commit(ctx context.Context) error {
	unit.owner.commits++
	if err := unit.unit.Commit(ctx); err != nil {
		return err
	}
	if unit.owner.unknown {
		return oidcauth.ErrCommitOutcomeUnknown
	}
	return nil
}
func (unit *integrationFailureTransaction) Rollback(ctx context.Context) error {
	return unit.unit.Rollback(ctx)
}

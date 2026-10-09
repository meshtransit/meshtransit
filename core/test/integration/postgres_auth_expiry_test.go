//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

const integrationExpirySQL = `SELECT transaction_version, transaction_consumed_at, expired_at,
    stream_internal_id, next_sequence, latest_event_hash FROM mesh_ops.expire_oidc_browser_v1(
    $1::UUID,$2::UUID,$3::BIGINT,$4::TIMESTAMPTZ,$5::TIMESTAMPTZ,$6::TIMESTAMPTZ,$7::BYTEA)`
const integrationExpiryCountSQL = `SELECT count(*) FROM mesh_ops.expire_oidc_browser_v1(
    $1::UUID,$2::UUID,$3::BIGINT,$4::TIMESTAMPTZ,$5::TIMESTAMPTZ,$6::TIMESTAMPTZ,$7::BYTEA)`
const integrationExpiryAppendSQL = `SELECT mesh_ops.append_oidc_expiry_evidence_v1(
    $1::UUID,$2::UUID,$3::BIGINT,$4::UUID,$5::UUID,$6::BIGINT,$7::BYTEA,$8::BYTEA,$9::BYTEA,$10::BYTEA,$11::JSONB)`

func assertPostgreSQLAbandonedExpiry(
	ctx context.Context, t *testing.T, admin, worker *pgx.Conn, workerPool, runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	options := postgresadapter.AuthTransactionOptions{StatementTimeout: 5 * time.Second, LockTimeout: 2 * time.Second, IdleTimeout: 10 * time.Second}
	store, err := postgresadapter.NewAuthExpiryStore(workerPool, options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postgresadapter.NewAuthExpiryStore(runtimePool, options); err == nil {
		t.Fatal("runtime admitted expiry store")
	}
	if _, err := postgresadapter.NewAuthTransactionStore(workerPool, options); err == nil {
		t.Fatal("worker admitted login store")
	}
	creation, err := postgresadapter.NewAuthTransactionStore(runtimePool, options)
	if err != nil {
		t.Fatal(err)
	}
	assertExpiryPrivileges(ctx, t, admin)
	var sessionsBefore []byte
	if err := admin.QueryRow(ctx, integrationExpirySessionStateSQL).Scan(&sessionsBefore); err != nil {
		t.Fatal(err)
	}
	for index, scenario := range []string{"pending", "consuming", "lost ACK", "quarantine", "provider revoked", "workspace revoked", "deployment deleted"} {
		t.Run("abandoned expiry "+scenario, func(t *testing.T) {
			snapshot := integrationExpirySnapshot(ctx, t, admin, creation, []string{"fd0", "fd1", "fd2", "fd3", "fd4", "fd5", "fd6"}[index], scenario == "consuming")
			if scenario == "quarantine" || scenario == "provider revoked" || scenario == "workspace revoked" || scenario == "deployment deleted" {
				setExpiryLifecycleFixture(ctx, t, admin, scenario, false)
				defer setExpiryLifecycleFixture(ctx, t, admin, scenario, true)
			}
			batch, err := store.ListDue(ctx, snapshot.DeploymentID(), 128)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, hint := range batch {
				if hint.Params() == snapshot.Params() {
					found = true
				}
			}
			if !found {
				t.Fatal("revoked/quarantined scope stranded open proof")
			}
			before := authAdmissionAuthorityCounts(ctx, t, admin)
			owner := &integrationExpiryTransactions{store: store, hideACK: scenario == "lost ACK"}
			service := integrationExpiryService(t, store, owner)
			result, err := service.Expire(ctx, snapshot)
			if scenario == "lost ACK" {
				if !errors.Is(err, oidcauth.ErrCommitOutcomeUnknown) || result.IsValid() {
					t.Fatal("unknown Commit released expiry receipt")
				}
			} else if err != nil || !result.IsValid() {
				t.Fatal("expiry failed", err)
			}
			if owner.commits != 1 {
				t.Fatal("expiry Commit retried")
			}
			assertExpiryEvidence(ctx, t, admin, owner.command)
			after := authAdmissionAuthorityCounts(ctx, t, admin)
			if after[0] != before[0] || after[1] != before[1]+1 || after[2] != before[2]+1 || after[3] != before[3]+1 || after[4] != before[4] {
				t.Fatal("expiry changed grant/revision or lost evidence")
			}
			if next, err := service.Expire(ctx, snapshot); err == nil || next.IsValid() || owner.commits != 1 {
				t.Fatal("stale expiry duplicated transition")
			}
			batch, err = store.ListDue(ctx, snapshot.DeploymentID(), 128)
			if err != nil {
				t.Fatal(err)
			}
			for _, hint := range batch {
				if hint.TransactionID() == snapshot.TransactionID() {
					t.Fatal("committed expiry remained selected")
				}
			}
		})
	}
	snapshot := integrationExpirySnapshot(ctx, t, admin, creation, "fd7", false)
	assertExpiryCASAndMissingEvidence(ctx, t, admin, worker, snapshot)
	other := integrationExpirySnapshot(ctx, t, admin, creation, "fd8", false)
	assertExpiryEvidenceOwnership(ctx, t, admin, worker, snapshot, other)
	assertExpiryIndependentUnits(ctx, t, admin, store, snapshot)
	assertExpiryWaitUsesFreshClock(ctx, t, admin, store, other)
	before := authAdmissionAuthorityCounts(ctx, t, admin)
	pass, err := integrationExpiryService(t, store, store).Sweep(ctx, snapshot.DeploymentID())
	if err != nil || pass.Attempted != pass.Confirmed {
		t.Fatal("bounded cleanup pass failed", err)
	}
	after := authAdmissionAuthorityCounts(ctx, t, admin)
	if after[0] != before[0] || after[4] != before[4] {
		t.Fatal("pass changed grant/revision authority")
	}
	var sessionsAfter []byte
	if err := admin.QueryRow(ctx, integrationExpirySessionStateSQL).Scan(&sessionsAfter); err != nil || !bytes.Equal(sessionsBefore, sessionsAfter) {
		t.Fatal("cleanup changed previously issued Session lifecycle", err)
	}
}

const integrationExpirySessionStateSQL = `SELECT COALESCE(jsonb_agg(jsonb_build_array(
    public_id,state,version,last_used_at,idle_expires_at,absolute_expires_at,ended_at,end_reason,updated_at)
    ORDER BY id),'[]'::JSONB) FROM mesh.account_session`

func integrationExpirySnapshot(
	ctx context.Context, t *testing.T, admin *pgx.Conn, store *postgresadapter.AuthTransactionStore, suffix string, consuming bool,
) oidcauth.ExpirySnapshot {
	t.Helper()
	verified := integrationClaimVerifiedRemaining(ctx, t, store, suffix, 500*time.Millisecond)
	pending := verified.Snapshot()
	params := oidcauth.ExpirySnapshotParams{
		DeploymentID: pending.Route().DeploymentID(), TransactionID: pending.TransactionID(), State: "pending", Version: 1,
		CreatedAt: pending.CreatedAt(), ExpiresAt: pending.ExpiresAt(), SemanticHash: pending.SemanticHash(),
	}
	if consuming {
		claim, err := oidcauth.NewClaimService(oidcauth.ClaimOptions{RequestTimeout: 5 * time.Second, RollbackTimeout: time.Second},
			oidcauth.ClaimDependencies{Transactions: store, IDs: oidcauth.SystemClaimIDs{}, Clock: oidcauth.SystemStartClock{}})
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := claim.ClaimBrowser(ctx, verified)
		if err != nil {
			t.Fatal(err)
		}
		params.State, params.Version, params.ConsumedAt = "consuming", 2, receipt.Claimed().ConsumedAt()
	}
	snapshot, err := oidcauth.NewExpirySnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	// Finite synthetic deadline wait, on the disposable DB only. Frozen Begin
	// time is not used to decide expiry in production.
	if _, err := admin.Exec(ctx, `SELECT pg_catalog.pg_sleep(GREATEST(0,
    EXTRACT(EPOCH FROM ($1::TIMESTAMPTZ-pg_catalog.clock_timestamp())) + 0.02))`, snapshot.ExpiresAt()); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func integrationExpiryService(t *testing.T, candidates oidcauth.ExpiryCandidates, transactions oidcauth.ExpiryTransactions) *oidcauth.ExpiryService {
	t.Helper()
	service, err := oidcauth.NewExpiryService(oidcauth.ExpiryOptions{BatchSize: 128, PassTimeout: 10 * time.Second, UnitTimeout: 5 * time.Second, RollbackTimeout: time.Second},
		oidcauth.ExpiryDependencies{Candidates: candidates, Transactions: transactions, IDs: oidcauth.SystemClaimIDs{}, Clock: oidcauth.SystemStartClock{}})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type integrationExpiryTransactions struct {
	store   *postgresadapter.AuthExpiryStore
	hideACK bool
	command oidcauth.ExpiryCommand
	commits int
}

func (owner *integrationExpiryTransactions) BeginExpiry(ctx context.Context, dep deployment.ID) (oidcauth.ExpiryTransaction, error) {
	unit, err := owner.store.BeginExpiry(ctx, dep)
	if unit == nil {
		return nil, err
	}
	return &integrationExpiryUnit{ExpiryTransaction: unit, owner: owner}, err
}

type integrationExpiryUnit struct {
	oidcauth.ExpiryTransaction
	owner *integrationExpiryTransactions
}

func (unit *integrationExpiryUnit) Expire(ctx context.Context, command oidcauth.ExpiryCommand) (oidcauth.Expired, error) {
	unit.owner.command = command
	return unit.ExpiryTransaction.Expire(ctx, command)
}
func (unit *integrationExpiryUnit) Commit(ctx context.Context) error {
	unit.owner.commits++
	if err := unit.ExpiryTransaction.Commit(ctx); err != nil {
		return err
	}
	if unit.owner.hideACK {
		return oidcauth.ErrCommitOutcomeUnknown
	}
	return nil
}

func integrationExpiryArgs(snapshot oidcauth.ExpirySnapshot) []any {
	hash := snapshot.SemanticHash()
	var consumed any
	if !snapshot.ConsumedAt().IsZero() {
		consumed = snapshot.ConsumedAt()
	}
	return []any{snapshot.DeploymentID().String(), snapshot.TransactionID().String(), snapshot.Version(), snapshot.CreatedAt(), snapshot.ExpiresAt(), consumed, hash[:]}
}

func assertExpiryCASAndMissingEvidence(ctx context.Context, t *testing.T, admin, worker *pgx.Conn, snapshot oidcauth.ExpirySnapshot) {
	t.Helper()
	for _, change := range []struct {
		name  string
		index int
		value any
	}{
		{"deployment", 0, "01890f00-0000-7000-8000-000000000002"}, {"transaction", 1, "01890f00-0000-7000-8000-000000000998"},
		{"version", 2, int64(2)}, {"created", 3, snapshot.CreatedAt().Add(time.Microsecond)}, {"deadline", 4, snapshot.ExpiresAt().Add(time.Microsecond)},
		{"claim", 5, snapshot.CreatedAt()}, {"hash", 6, bytes.Repeat([]byte{2}, 32)}, {"null hash", 6, nil}, {"zero hash", 6, make([]byte, 32)}, {"valid rollback", -1, nil},
	} {
		t.Run("expiry CAS "+change.name, func(t *testing.T) {
			probe, err := worker.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackIntegrationTransaction(ctx, t, probe)
			ids, err := (oidcauth.SystemClaimIDs{}).NewClaimIDs()
			if err != nil {
				t.Fatal(err)
			}
			setIntegrationChange(ctx, t, probe, ids.ChangeID().String())
			args := integrationExpiryArgs(snapshot)
			if change.index >= 0 {
				args[change.index] = change.value
			}
			var count int
			if err := probe.QueryRow(ctx, integrationExpiryCountSQL, args...).Scan(&count); err != nil {
				t.Fatal(err)
			}
			want := 0
			if change.index < 0 {
				want = 1
			}
			if count != want {
				t.Fatal("expiry CAS scope bypass")
			}
			assertAdmissionScopeCleared(ctx, t, probe)
			if change.index < 0 {
				if err := probe.Commit(ctx); err == nil {
					t.Fatal("erasure committed without matching evidence")
				}
				assertExpiryStillOpen(ctx, t, admin, snapshot)
			}
		})
	}
}

func assertExpiryStillOpen(ctx context.Context, t *testing.T, admin *pgx.Conn, snapshot oidcauth.ExpirySnapshot) {
	t.Helper()
	var intact bool
	if err := admin.QueryRow(ctx, `SELECT state=$2::TEXT AND version=$3::BIGINT AND consumed_at IS NOT DISTINCT FROM $4::TIMESTAMPTZ
    AND pkce_verifier_encryption_algorithm IS NOT NULL AND pkce_verifier_encryption_key_id IS NOT NULL
    AND pkce_verifier_ciphertext IS NOT NULL FROM mesh.auth_transaction WHERE public_id=$1::UUID`,
		snapshot.TransactionID().String(), snapshot.State(), snapshot.Version(), integrationExpiryArgs(snapshot)[5]).Scan(&intact); err != nil || !intact {
		t.Fatal("failed unit did not roll back proof/state", err)
	}
}

func assertExpiryEvidence(ctx context.Context, t *testing.T, admin *pgx.Conn, command oidcauth.ExpiryCommand) {
	t.Helper()
	snapshot, ids := command.Snapshot(), command.MutationIDs()
	var at time.Time
	var before, after, binding, eventHash, previousHash, payload, outboxPayload []byte
	var safe bool
	if err := admin.QueryRow(ctx, `SELECT auth.updated_at,audit.before_semantic_hash,audit.after_semantic_hash,auth.binding_semantic_hash,
    identity.event_hash,identity.previous_event_hash,audit.payload,outbox.payload,
    auth.state='expired' AND auth.failure_class='deadline_expired' AND auth.version=$3::BIGINT
    AND auth.pkce_verifier_encryption_algorithm IS NULL AND auth.pkce_verifier_encryption_key_id IS NULL
    AND auth.pkce_verifier_ciphertext IS NULL AND auth.principal_id IS NULL AND auth.consumed_result_kind IS NULL
    AND auth.consumed_result_public_id IS NULL AND audit.actor_principal_public_id IS NULL AND audit.network_id IS NULL
    AND audit.action='auth_transaction.expired' AND audit.permission='system.lifecycle' AND outbox.network_revision IS NULL
    AND outbox.aggregate_version=auth.version AND outbox.event_class='identity.auth_transaction.expired'
    AND mutation.before_version=$4::BIGINT AND mutation.after_version=auth.version
    AND auth.consumed_at=(audit.payload->>'consumed_at')::TIMESTAMPTZ
    FROM mesh.auth_transaction auth JOIN mesh_audit.authority_mutation mutation
    ON mutation.row_public_id=auth.public_id AND mutation.aggregate_kind='auth_transaction' AND mutation.change_public_id=$2::UUID
    JOIN mesh_audit.audit_event_identity identity ON identity.change_public_id=mutation.change_public_id AND identity.transaction_id=mutation.transaction_id
    JOIN mesh_audit.audit_event audit ON audit.event_identity_id=identity.id AND audit.occurred_at=identity.occurred_at
    JOIN mesh_ops.outbox_event outbox ON outbox.change_public_id=mutation.change_public_id AND outbox.transaction_id=mutation.transaction_id
    WHERE auth.public_id=$1::UUID`, snapshot.TransactionID().String(), ids.ChangeID().String(), snapshot.Version()+1, snapshot.Version()).Scan(
		&at, &before, &after, &binding, &eventHash, &previousHash, &payload, &outboxPayload, &safe); err != nil || !safe {
		t.Fatal("expiry durable no-grant evidence invalid", err)
	}
	terminal, err := oidcauth.NewExpired(snapshot, at)
	if err != nil {
		t.Fatal(err)
	}
	wantBefore, wantAfter, wantBinding := terminal.BeforeSemanticHash(), terminal.AfterSemanticHash(), snapshot.SemanticHash()
	if !bytes.Equal(before, wantBefore[:]) || !bytes.Equal(after, wantAfter[:]) || !bytes.Equal(binding, wantBinding[:]) || !bytes.Equal(payload, outboxPayload) {
		t.Fatal("expiry original/terminal payload hashes diverged")
	}
	// Reconstruct the precise application JSON representation before hashing;
	// PostgreSQL JSONB's key order/spacing is not the event-hash input encoding.
	var decoded integrationExpiryPayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	var previous [32]byte
	copy(previous[:], previousHash)
	wantHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previous, EventID: ids.AuditEventID(), ChangeID: ids.ChangeID(), AggregateKind: "auth_transaction",
		AggregateID: publicid.ID(snapshot.TransactionID()), AggregateVersion: terminal.Version(), Action: "auth_transaction.expired",
		Permission: "system.lifecycle", CorrelationID: publicid.ID(snapshot.TransactionID()), BeforeSemanticHash: wantBefore,
		AfterSemanticHash: wantAfter, AuditPayloadHash: sha256.Sum256(canonical), OutboxEventClass: "identity.auth_transaction.expired", OutboxPayloadHash: sha256.Sum256(canonical),
	})
	if err != nil || !bytes.Equal(eventHash, wantHash[:]) {
		t.Fatal("expiry audit chain hash invalid", err)
	}
}

type integrationExpiryPayload struct {
	TransactionID   string    `json:"transaction_public_id"`
	PreviousState   string    `json:"previous_state"`
	PreviousVersion int64     `json:"previous_version"`
	ExpiresAt       time.Time `json:"expires_at"`
	ConsumedAt      time.Time `json:"consumed_at"`
	ExpiredAt       time.Time `json:"expired_at"`
}

func setExpiryLifecycleFixture(ctx context.Context, t *testing.T, admin *pgx.Conn, scenario string, restore bool) {
	t.Helper()
	ids, err := (oidcauth.SystemClaimIDs{}).NewClaimIDs()
	if err != nil {
		t.Fatal(err)
	}
	evidence := authorityEvidenceFixture{changePublicID: ids.ChangeID().String(), eventPublicID: ids.AuditEventID().String(), outboxPublicID: ids.OutboxEventID().String(), streamID: 1}
	var version int64
	var read, mutate string
	switch scenario {
	case "quarantine":
		read = `SELECT version FROM mesh.deployment WHERE id=1`
		mutate = `UPDATE mesh.deployment SET recovery_state=CASE WHEN $1::BOOLEAN THEN 'verified' ELSE 'quarantined' END,
    version=version+1,updated_at=GREATEST(updated_at,clock_timestamp()) WHERE id=1`
		evidence.aggregateKind, evidence.aggregatePublicID, evidence.permission = "deployment", "01890f00-0000-7000-8000-000000000001", "deployment.manage"
	case "deployment deleted":
		read = `SELECT version FROM mesh.deployment WHERE id=1`
		mutate = `UPDATE mesh.deployment SET state=CASE WHEN $1::BOOLEAN THEN 'active' ELSE 'deleted' END,
    deleted_at=CASE WHEN $1::BOOLEAN THEN NULL ELSE clock_timestamp() END,version=version+1,
    updated_at=GREATEST(updated_at,clock_timestamp()) WHERE id=1`
		evidence.aggregateKind, evidence.aggregatePublicID, evidence.permission = "deployment", "01890f00-0000-7000-8000-000000000001", "deployment.manage"
	case "provider revoked":
		read = `SELECT version FROM mesh.identity_provider WHERE public_id='01890f00-0000-7000-8000-000000000601'::UUID`
		mutate = `UPDATE mesh.identity_provider SET state=CASE WHEN $1::BOOLEAN THEN 'active' ELSE 'suspended' END,
    version=version+1,updated_at=GREATEST(updated_at,clock_timestamp()) WHERE public_id='01890f00-0000-7000-8000-000000000601'::UUID`
		evidence.aggregateKind, evidence.aggregatePublicID, evidence.permission = "identity_provider", "01890f00-0000-7000-8000-000000000601", "identity_provider.manage"
	case "workspace revoked":
		read = `SELECT version FROM mesh.workspace WHERE id=101`
		mutate = `UPDATE mesh.workspace SET state=CASE WHEN $1::BOOLEAN THEN 'active' ELSE 'suspended' END,
    version=version+1,updated_at=GREATEST(updated_at,clock_timestamp()) WHERE id=101`
		evidence.aggregateKind, evidence.aggregatePublicID, evidence.permission = "workspace", "01890f00-0000-7000-8000-000000000101", "workspace.manage"
	default:
		t.Fatal("invalid synthetic lifecycle scenario")
	}
	if err := admin.QueryRow(ctx, read).Scan(&version); err != nil {
		t.Fatal(err)
	}
	evidence.aggregateVersion, evidence.action, evidence.outboxEventClass = version+1, evidence.aggregateKind+".updated", evidence.aggregateKind+".updated"
	commitAuditedAuthorityFixture(ctx, t, admin, evidence, func(tx pgx.Tx) {
		if _, err := tx.Exec(ctx, mutate, restore); err != nil {
			t.Fatal(err)
		}
	})
}

func assertExpiryPrivileges(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var count int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
    JOIN pg_catalog.pg_roles owner ON owner.oid=p.proowner WHERE n.nspname='mesh_ops'
    AND p.proname IN ('list_due_oidc_browser_v1','expire_oidc_browser_v1','append_oidc_expiry_evidence_v1')
    AND p.prosecdef AND owner.rolname='mesh_migrator' AND NOT owner.rolsuper AND NOT owner.rolbypassrls
    AND p.proconfig IS NOT NULL AND has_function_privilege('mesh_worker',p.oid,'EXECUTE')
    AND NOT has_function_privilege('mesh_runtime',p.oid,'EXECUTE') AND NOT has_function_privilege('mesh_observer',p.oid,'EXECUTE')`).Scan(&count); err != nil || count != 3 {
		t.Fatal("expiry hardened function grant profile", err)
	}
	var forbidden bool
	if err := admin.QueryRow(ctx, `SELECT has_table_privilege('mesh_worker','mesh.auth_transaction','SELECT,INSERT,UPDATE,DELETE')
    OR has_table_privilege('mesh_worker','mesh.account_session','SELECT,INSERT,UPDATE,DELETE')
    OR has_function_privilege('mesh_worker','mesh_audit.lock_deployment_stream_head(uuid)','EXECUTE')
    OR has_function_privilege('mesh_worker','mesh_audit.append_authority_evidence(bigint,uuid,uuid,bigint,bytea,bytea,text,uuid,bigint,bigint,uuid,text,text,uuid,bytea,bytea,jsonb,text,jsonb)','EXECUTE')`).Scan(&forbidden); err != nil || forbidden {
		t.Fatal("worker expiry widened serving/audit grants", err)
	}
}

func assertExpiryIndependentUnits(ctx context.Context, t *testing.T, admin *pgx.Conn, store *postgresadapter.AuthExpiryStore, snapshot oidcauth.ExpirySnapshot) {
	t.Helper()
	var owners [2]*integrationExpiryTransactions
	var results [2]oidcauth.ExpiryResult
	var failures [2]error
	gate := make(chan struct{})
	var tasks sync.WaitGroup
	for index := range results {
		owners[index] = &integrationExpiryTransactions{store: store}
		service := integrationExpiryService(t, store, owners[index])
		tasks.Go(func() { <-gate; results[index], failures[index] = service.Expire(ctx, snapshot) })
	}
	close(gate)
	tasks.Wait()
	winners := 0
	for index := range results {
		if failures[index] == nil && results[index].IsValid() {
			winners++
			assertExpiryEvidence(ctx, t, admin, owners[index].command)
		}
	}
	if winners != 1 || owners[0].commits+owners[1].commits != 1 {
		t.Fatal("independent expiry units duplicated")
	}
}

func expiryProbeAppendArgs(ctx context.Context, t *testing.T, probe pgx.Tx, snapshot oidcauth.ExpirySnapshot) []any {
	t.Helper()
	ids, err := (oidcauth.SystemClaimIDs{}).NewClaimIDs()
	if err != nil {
		t.Fatal(err)
	}
	setIntegrationChange(ctx, t, probe, ids.ChangeID().String())
	var version, stream, sequence int64
	var at, consumed time.Time
	var previousHash []byte
	if err := probe.QueryRow(ctx, integrationExpirySQL, integrationExpiryArgs(snapshot)...).Scan(&version, &consumed, &at, &stream, &sequence, &previousHash); err != nil {
		t.Fatal(err)
	}
	terminal, err := oidcauth.NewExpired(snapshot, at)
	if err != nil || version != terminal.Version() || !consumed.Equal(terminal.ConsumedAt()) {
		t.Fatal("expiry probe metadata", err)
	}
	payload, err := json.Marshal(integrationExpiryPayload{
		TransactionID: snapshot.TransactionID().String(), PreviousState: snapshot.State(), PreviousVersion: snapshot.Version(),
		ExpiresAt: snapshot.ExpiresAt(), ConsumedAt: terminal.ConsumedAt(), ExpiredAt: terminal.ExpiredAt(),
	})
	if err != nil {
		t.Fatal(err)
	}
	before, after := terminal.BeforeSemanticHash(), terminal.AfterSemanticHash()
	var previous [32]byte
	copy(previous[:], previousHash)
	hash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previous, EventID: ids.AuditEventID(), ChangeID: ids.ChangeID(), AggregateKind: "auth_transaction",
		AggregateID: publicid.ID(snapshot.TransactionID()), AggregateVersion: version, Action: "auth_transaction.expired",
		Permission: "system.lifecycle", CorrelationID: publicid.ID(snapshot.TransactionID()), BeforeSemanticHash: before, AfterSemanticHash: after,
		AuditPayloadHash: sha256.Sum256(payload), OutboxEventClass: "identity.auth_transaction.expired", OutboxPayloadHash: sha256.Sum256(payload),
	})
	if err != nil {
		t.Fatal(err)
	}
	return []any{snapshot.DeploymentID().String(), snapshot.TransactionID().String(), stream, ids.AuditEventID().String(), ids.OutboxEventID().String(), sequence,
		previousHash, hash[:], before[:], after[:], payload}
}

func assertExpiryEvidenceOwnership(ctx context.Context, t *testing.T, admin, worker *pgx.Conn, snapshot, other oidcauth.ExpirySnapshot) {
	t.Helper()
	for _, candidate := range []struct {
		name  string
		index int
		value any
	}{
		{"null sequence", 5, nil}, {"null previous hash", 6, nil}, {"null event hash", 7, nil}, {"short previous hash", 6, make([]byte, 31)},
		{"zero event hash", 7, make([]byte, 32)}, {"wrong deployment", 0, "01890f00-0000-7000-8000-000000000002"},
		{"wrong stream", 2, int64(2)}, {"wrong auth", 1, other.TransactionID().String()}, {"null payload", 10, nil},
		{"duplicate append", -1, nil}, {"second same change", -2, nil}, {"second fresh change", -3, nil},
	} {
		t.Run("expiry evidence ownership "+candidate.name, func(t *testing.T) {
			probe, err := worker.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackIntegrationTransaction(ctx, t, probe)
			args := expiryProbeAppendArgs(ctx, t, probe, snapshot)
			if candidate.index >= 0 {
				args[candidate.index] = candidate.value
			}
			var sequence int64
			if candidate.index >= 0 {
				if err := probe.QueryRow(ctx, integrationExpiryAppendSQL, args...).Scan(&sequence); err == nil {
					t.Fatal("malformed expiry evidence appended")
				}
			} else {
				if err := probe.QueryRow(ctx, integrationExpiryAppendSQL, args...).Scan(&sequence); err != nil {
					t.Fatal("valid expiry evidence probe", err)
				}
				if candidate.index == -1 {
					if err := probe.QueryRow(ctx, integrationExpiryAppendSQL, args...).Scan(&sequence); err == nil {
						t.Fatal("duplicate expiry pair appended")
					}
				} else {
					if candidate.index == -3 {
						ids, err := (oidcauth.SystemClaimIDs{}).NewClaimIDs()
						if err != nil {
							t.Fatal(err)
						}
						setIntegrationChange(ctx, t, probe, ids.ChangeID().String())
					}
					var count int
					if err := probe.QueryRow(ctx, integrationExpiryCountSQL, integrationExpiryArgs(other)...).Scan(&count); err == nil {
						t.Fatal("second Auth borrowed evidence/lock order in same owned unit")
					}
				}
			}
			if err := probe.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			assertExpiryStillOpen(ctx, t, admin, snapshot)
			assertExpiryStillOpen(ctx, t, admin, other)
		})
	}
}

func assertExpiryWaitUsesFreshClock(ctx context.Context, t *testing.T, admin *pgx.Conn, store *postgresadapter.AuthExpiryStore, snapshot oidcauth.ExpirySnapshot) {
	t.Helper()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	held, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackIntegrationTransaction(ctx, t, held)
	if _, err := held.Exec(ctx, `SELECT id FROM mesh_audit.audit_stream WHERE id=1 FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	owner := &integrationExpiryTransactions{store: store}
	service := integrationExpiryService(t, store, owner)
	type completion struct {
		result oidcauth.ExpiryResult
		err    error
	}
	finished := make(chan completion, 1)
	go func() {
		result, err := service.Expire(ctx, snapshot)
		finished <- completion{result, err}
		close(finished)
	}()
	defer func() {
		cancel()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case <-finished:
		case <-timer.C:
			t.Error("expiry test did not join canceled work")
		}
	}()
	for {
		var waiting bool
		// pg_stat_activity snapshots are cached inside a transaction. Refresh
		// before observing a worker connection created after the head blocker.
		if _, err := held.Exec(ctx, `SELECT pg_catalog.pg_stat_clear_snapshot()`); err != nil {
			t.Fatal(err)
		}
		if err := held.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity
    WHERE usename='mesh_worker' AND wait_event_type='Lock' AND query LIKE '%expire_oidc_browser_v1%')`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case early := <-finished:
			timer.Stop()
			t.Fatal("expiry did not wait for head", early.err)
		case <-ctx.Done():
			timer.Stop()
			t.Fatal(ctx.Err())
		case <-timer.C:
		}
	}
	var releaseTime time.Time
	if err := held.QueryRow(ctx, `SELECT pg_catalog.clock_timestamp()`).Scan(&releaseTime); err != nil {
		t.Fatal(err)
	}
	if err := held.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case done := <-finished:
		if done.err != nil || !done.result.IsValid() || done.result.Expired().ExpiredAt().Before(releaseTime) {
			t.Fatal("expiry decision used frozen/pre-head clock", done.err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	assertExpiryEvidence(ctx, t, admin, owner.command)
}

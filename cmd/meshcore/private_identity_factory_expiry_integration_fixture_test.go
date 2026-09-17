//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/meshtransit/meshtransit/internal/adapter/oidc"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/authexpiry"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

func (storage *privateFactoryIntegrationStorage) openExpiryWorkerPool(t *testing.T) *postgresadapter.Pool {
	t.Helper()
	return storage.openPrivateFactoryWorkerPool(t, "meshtransit_private_factory_expiry")
}

func (storage *privateFactoryIntegrationStorage) openConsumingWorkerPool(t *testing.T) *postgresadapter.Pool {
	t.Helper()
	return storage.openPrivateFactoryWorkerPool(t, "meshtransit_private_factory_consuming")
}

func (storage *privateFactoryIntegrationStorage) openPrivateFactoryWorkerPool(
	t *testing.T,
	database string,
) *postgresadapter.Pool {
	t.Helper()
	process, err := config.Load(os.LookupEnv)
	if err != nil || process.Storage == nil || process.Storage.PostgreSQL.Worker == nil {
		t.Fatal("load owned expiry worker credentials")
	}
	pg := process.Storage.PostgreSQL
	allowed := database == "meshtransit_private_factory_expiry" || database == "meshtransit_private_factory_consuming" ||
		database == "meshtransit_private_factory_abandoned" || database == "meshtransit_private_factory_ack"
	owned := allowed && pg.Address == "meshtransit-postgres:5432" && pg.Database == database
	if !owned || pg.Worker.User != "mesh_worker" {
		t.Fatal("refuse unowned expiry worker scope")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	pool, err := openPostgresRolePool(ctx, postgresadapter.PoolRoleWorker, pg, *pg.Worker, 5*time.Second)
	if err != nil {
		t.Fatal("open real expiry worker pool")
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer stop()
		if database == "meshtransit_private_factory_ack" {
			if closePrivateFactoryACKPool(cleanup, pool) != nil {
				t.Error("close positively idle owned ACK expiry worker pool")
			}
			return
		}
		if pool.Shutdown(cleanup) != nil {
			t.Error("close owned expiry worker pool")
		}
	})
	if pool.Check(ctx) != nil {
		t.Fatal("verify owned expiry worker role/schema")
	}
	return pool
}

func startPrivateFactoryExpiryWorker(
	t *testing.T,
	settings config.AuthExpiryConfig,
	pool *postgresadapter.Pool,
) (*authexpiry.Worker, *prometheus.Registry) {
	t.Helper()
	telemetry := oidc.NewExpiryTelemetry()
	registry := prometheus.NewPedanticRegistry()
	if registry.Register(telemetry) != nil {
		t.Fatal("register isolated expiry telemetry")
	}
	worker, err := composeAuthExpiry(settings, pool, telemetry, discardCompositionLogger())
	if err != nil || worker == nil || worker.Start(t.Context()) != nil {
		t.Fatal("start concrete owned expiry worker")
	}
	// Worker shutdown/join precedes pool and HTTP/key/Redis cleanup, including
	// failed assertions. Explicit joins are repeatable on the closed Done channel.
	t.Cleanup(func() { stopPrivateFactoryExpiryWorker(t, worker) })
	return worker, registry
}

func (storage *privateFactoryIntegrationStorage) originalPendingExpiry(
	t *testing.T,
	transactionID string,
	dep deployment.ID,
) oidcauth.ExpirySnapshot {
	t.Helper()
	id, err := publicid.Parse(transactionID)
	if err != nil {
		t.Fatal("parse original factory transaction identity")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	params := oidcauth.ExpirySnapshotParams{
		DeploymentID: dep, TransactionID: oidcauth.TransactionID(id), State: "pending", Version: 1,
	}
	var hash []byte
	if storage.admin.QueryRow(ctx, `SELECT auth.created_at,auth.expires_at,auth.binding_semantic_hash
FROM mesh.auth_transaction auth JOIN mesh.deployment d ON d.id=auth.deployment_id
WHERE auth.public_id=$1::UUID AND d.installation_public_id=$2::UUID
AND auth.state='pending' AND auth.version=1 AND auth.consumed_at IS NULL`,
		transactionID, dep.String()).Scan(&params.CreatedAt, &params.ExpiresAt, &hash) != nil || len(hash) != sha256.Size {
		t.Fatal("read immutable original factory metadata")
	}
	copy(params.SemanticHash[:], hash)
	snapshot, err := oidcauth.NewExpirySnapshot(params)
	if err != nil || snapshot.ExpiresAt().Sub(snapshot.CreatedAt()) != time.Minute {
		t.Fatal("factory did not preserve minimum original lifetime")
	}
	storage.assertOriginalPendingExpiry(t, snapshot)
	return snapshot
}

func (storage *privateFactoryIntegrationStorage) assertOriginalPendingExpiry(t *testing.T, snapshot oidcauth.ExpirySnapshot) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	hash := snapshot.SemanticHash()
	var intact bool
	if storage.admin.QueryRow(ctx, `SELECT state='pending' AND version=1 AND consumed_at IS NULL
AND created_at=$2 AND expires_at=$3 AND binding_semantic_hash=$4 AND expires_at>pg_catalog.clock_timestamp()
AND flow_kind='browser_authorization_code' AND operation_kind='login' AND principal_id IS NULL
AND failure_class IS NULL AND consumed_result_kind IS NULL AND consumed_result_public_id IS NULL
AND pkce_verifier_encryption_algorithm IS NOT NULL AND pkce_verifier_encryption_key_id IS NOT NULL
AND pkce_verifier_ciphertext IS NOT NULL FROM mesh.auth_transaction WHERE public_id=$1::UUID`,
		snapshot.TransactionID().String(), snapshot.CreatedAt(), snapshot.ExpiresAt(), hash[:]).Scan(&intact) != nil || !intact {
		t.Fatal("live original pending metadata/proof was changed or expired early")
	}
}

// This privileged synthetic fixture models the fence only, never a witnessed
// recovery or recovery-controller semantic hash. Fresh evidence precedes Begin.
func (storage *privateFactoryIntegrationStorage) quarantineFixtureDeployment(t *testing.T) {
	t.Helper()
	_, ids, err := (oidcauth.SystemStartIDs{}).NewStartIDs()
	if err != nil {
		t.Fatal("generate fresh quarantine fixture evidence identities")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tx, err := storage.admin.Begin(ctx)
	if err != nil {
		t.Fatal("begin audited quarantine fixture mutation")
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		if err := tx.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Error("rollback quarantine fixture mutation")
		}
	}()
	if _, err := tx.Exec(ctx, "SELECT pg_catalog.set_config('mesh.change_public_id',$1,TRUE)", ids.ChangeID().String()); err != nil {
		t.Fatal("bind quarantine fixture mutation identity")
	}
	privateFactoryExec(ctx, t, tx, `UPDATE mesh.deployment
SET version=2,authority_generation=2,recovery_epoch=2,recovery_state='quarantined'
WHERE id=1 AND version=1 AND authority_generation=1 AND recovery_epoch=1 AND recovery_state='verified'`)
	var sequence, appended int64
	var previous []byte
	if tx.QueryRow(ctx, `SELECT next_sequence,latest_event_hash FROM mesh_audit.audit_stream
WHERE id=1 AND deployment_id=1 AND scope_kind='deployment' FOR UPDATE`).Scan(&sequence, &previous) != nil ||
		len(previous) != sha256.Size {
		t.Fatal("lock exact quarantine fixture audit head")
	}
	payload := []byte(`{"recovery_epoch":2,"recovery_state":"quarantined"}`)
	before := sha256.Sum256([]byte("meshtransit/fixture/quarantine/verified-v1"))
	after := sha256.Sum256(payload)
	var previousHash [32]byte
	copy(previousHash[:], previous)
	target := privateIdentityID(t, 1)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: ids.AuditEventID(), ChangeID: ids.ChangeID(),
		AggregateKind: "deployment", AggregateID: target, AggregateVersion: 2,
		Action: "deployment.recovery_quarantined", Permission: "system.bootstrap",
		BeforeSemanticHash: before, AfterSemanticHash: after, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: "deployment.recovery_quarantined", OutboxPayloadHash: sha256.Sum256(payload),
	})
	if err != nil {
		t.Fatal("prepare canonical quarantine fixture evidence")
	}
	if tx.QueryRow(ctx, `SELECT mesh_audit.append_authority_evidence(
1,$1::UUID,$2::UUID,$3::BIGINT,$4::BYTEA,$5::BYTEA,'deployment',$6::UUID,2,NULL::BIGINT,NULL::UUID,
'deployment.recovery_quarantined','system.bootstrap',NULL::UUID,$7::BYTEA,$8::BYTEA,$9::JSONB,
'deployment.recovery_quarantined',$9::JSONB)`,
		ids.AuditEventID().String(), ids.OutboxEventID().String(), sequence, previous, eventHash[:],
		target.String(), before[:], after[:], payload).Scan(&appended) != nil || appended != sequence {
		t.Fatal("append exact version-two quarantine fixture evidence")
	}
	if tx.Commit(ctx) != nil {
		t.Fatal("commit audited quarantine fixture mutation")
	}
}

func (storage *privateFactoryIntegrationStorage) assertNaturalPendingExpiry(t *testing.T, snapshot oidcauth.ExpirySnapshot) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var at time.Time
	var before, after, binding, eventHash, previous, payload, outboxPayload []byte
	var eventText, changeText string
	var safe bool
	if storage.admin.QueryRow(ctx, `SELECT auth.updated_at,e.before_semantic_hash,e.after_semantic_hash,
auth.binding_semantic_hash,i.event_hash,i.previous_event_hash,e.payload,o.payload,i.public_id::TEXT,i.change_public_id::TEXT,
auth.state='expired' AND auth.version=2 AND auth.failure_class='deadline_expired'
AND auth.created_at=$2 AND auth.expires_at=$3 AND auth.consumed_at=auth.updated_at AND auth.updated_at>=auth.expires_at
AND auth.principal_id IS NULL AND auth.operation_kind='login' AND auth.flow_kind='browser_authorization_code'
AND auth.consumed_result_kind IS NULL AND auth.consumed_result_public_id IS NULL
AND auth.pkce_verifier_encryption_algorithm IS NULL AND auth.pkce_verifier_encryption_key_id IS NULL
AND auth.pkce_verifier_ciphertext IS NULL AND auth.deployment_recovery_epoch=1
AND d.installation_public_id=$4::UUID AND d.version=2 AND d.authority_generation=2
AND d.recovery_epoch=2 AND d.recovery_state='quarantined'
AND m.before_version=1 AND m.after_version=2 AND m.operation='update'
AND e.target_kind='auth_transaction' AND e.target_public_id=auth.public_id
AND e.action='auth_transaction.expired' AND e.permission='system.lifecycle'
AND e.actor_principal_public_id IS NULL AND e.network_id IS NULL AND e.correlation_public_id=auth.public_id
AND o.aggregate_kind='auth_transaction' AND o.aggregate_public_id=auth.public_id AND o.aggregate_version=2
AND o.event_class='identity.auth_transaction.expired' AND o.network_revision IS NULL
AND s.id=1 AND s.deployment_id=auth.deployment_id AND s.scope_kind='deployment'
AND i.previous_event_hash=(SELECT prior.event_hash FROM mesh_audit.audit_event_identity prior
WHERE prior.stream_id=i.stream_id AND prior.stream_sequence=i.stream_sequence-1)
FROM mesh.auth_transaction auth JOIN mesh.deployment d ON d.id=auth.deployment_id
JOIN mesh_audit.authority_mutation m ON m.row_public_id=auth.public_id AND m.aggregate_kind='auth_transaction' AND m.after_version=2
JOIN mesh_audit.audit_event_identity i ON i.change_public_id=m.change_public_id AND i.transaction_id=m.transaction_id
JOIN mesh_audit.audit_stream s ON s.id=i.stream_id
JOIN mesh_audit.audit_event e ON e.event_identity_id=i.id AND e.occurred_at=i.occurred_at
JOIN mesh_ops.outbox_event o ON o.change_public_id=m.change_public_id AND o.transaction_id=m.transaction_id
WHERE auth.public_id=$1::UUID`,
		snapshot.TransactionID().String(), snapshot.CreatedAt(), snapshot.ExpiresAt(), snapshot.DeploymentID().String()).Scan(
		&at, &before, &after, &binding, &eventHash, &previous, &payload, &outboxPayload, &eventText, &changeText, &safe,
	) != nil || !safe || len(previous) != sha256.Size || len(eventHash) != sha256.Size {
		t.Fatal("natural pending expiry lost exact atomic no-grant evidence")
	}
	eventID, eventErr := publicid.Parse(eventText)
	changeID, changeErr := publicid.Parse(changeText)
	if eventErr != nil || changeErr != nil {
		t.Fatal("decode fresh expiry evidence identities")
	}
	terminal, err := oidcauth.NewExpired(snapshot, at)
	if err != nil {
		t.Fatal("validate original exclusive deadline decision")
	}
	wantBefore, wantAfter, wantBinding := terminal.BeforeSemanticHash(), terminal.AfterSemanticHash(), snapshot.SemanticHash()
	if !bytes.Equal(before, wantBefore[:]) || !bytes.Equal(after, wantAfter[:]) ||
		!bytes.Equal(binding, wantBinding[:]) || !bytes.Equal(payload, outboxPayload) {
		t.Fatal("natural pending expiry changed original/terminal lifecycle hashes")
	}
	var decoded privateFactoryExpiryPayload
	if json.Unmarshal(payload, &decoded) != nil || decoded.TransactionID != snapshot.TransactionID().String() ||
		decoded.PreviousState != "pending" || decoded.PreviousVersion != 1 || !decoded.ExpiresAt.Equal(snapshot.ExpiresAt()) ||
		!decoded.ConsumedAt.Equal(at) || !decoded.ExpiredAt.Equal(at) {
		t.Fatal("natural pending expiry payload changed original or terminal metadata")
	}
	canonical, err := json.Marshal(decoded)
	if err != nil {
		t.Fatal("encode canonical expiry payload")
	}
	var previousHash [32]byte
	copy(previousHash[:], previous)
	wantHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: eventID, ChangeID: changeID,
		AggregateKind: "auth_transaction", AggregateID: publicid.ID(snapshot.TransactionID()), AggregateVersion: 2,
		Action: "auth_transaction.expired", Permission: "system.lifecycle", CorrelationID: publicid.ID(snapshot.TransactionID()),
		BeforeSemanticHash: wantBefore, AfterSemanticHash: wantAfter, AuditPayloadHash: sha256.Sum256(canonical),
		OutboxEventClass: "identity.auth_transaction.expired", OutboxPayloadHash: sha256.Sum256(canonical),
	})
	if err != nil || !bytes.Equal(eventHash, wantHash[:]) {
		t.Fatal("natural pending expiry audit hash is not canonical")
	}
}

type privateFactoryExpiryPayload struct {
	TransactionID   string    `json:"transaction_public_id"`
	PreviousState   string    `json:"previous_state"`
	PreviousVersion int64     `json:"previous_version"`
	ExpiresAt       time.Time `json:"expires_at"`
	ConsumedAt      time.Time `json:"consumed_at"`
	ExpiredAt       time.Time `json:"expired_at"`
}

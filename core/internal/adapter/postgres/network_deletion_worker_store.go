package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/network/deletion"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	prepareNetworkDeletionStepSQL  = `SELECT mesh_ops.prepare_network_deletion_step_v1($1::UUID,$2::UUID,$3::INTEGER)::TEXT`
	finalizeNetworkDeletionStepSQL = `SELECT mesh_ops.finalize_network_deletion_step_v1($1::UUID,$2::JSONB)`
	networkDeletionLagSQL          = `SELECT pending, oldest_requested_at FROM mesh_ops.network_deletion_lag_v1($1::UUID)`
)

// ErrNetworkDeletionWorker reports a failed or uncertain phase-2 step.
var ErrNetworkDeletionWorker = errors.New("postgres network deletion worker failed")

// NetworkDeletionWorkerStore runs phase 2 of Network deletion on the worker
// pool: one step, its evidence hashed here, in one transaction.
type NetworkDeletionWorkerStore struct{ database outboxDatabase }

var _ deletion.WorkerStore = (*NetworkDeletionWorkerStore)(nil)

// NewNetworkDeletionWorkerStore rejects non-worker pools.
func NewNetworkDeletionWorkerStore(pool *Pool) (*NetworkDeletionWorkerStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, deletion.ErrInvalid
	}
	return &NetworkDeletionWorkerStore{database: pool.outboxDatabase}, nil
}

type networkDeletionStepProof struct {
	Changed bool `json:"changed"`
	// Failed counts deletions whose step failed and was rolled back.
	Failed           int    `json:"failed"`
	Completed        bool   `json:"completed"`
	ChangeID         string `json:"change_id"`
	NetworkID        string `json:"network_id"`
	AggregateVersion int64  `json:"aggregate_version"`
	Action           string `json:"action"`
	StreamID         int64  `json:"stream_id"`
	Sequence         int64  `json:"sequence"`
	PreviousHash     string `json:"previous_hash"`
	NetworkRevision  int64  `json:"network_revision"`
	AuditPayload     string `json:"audit_payload"`
	OutboxPayload    string `json:"outbox_payload"`
}

type networkDeletionStepAudit struct {
	DevicesRevoked int `json:"devices_revoked"`
}

func decodeNetworkDeletionStepProof(encoded string, change publicid.ID) (networkDeletionStepProof, error) {
	if len(encoded) == 0 || len(encoded) > 65536 {
		return networkDeletionStepProof{}, ErrNetworkDeletionWorker
	}
	var proof networkDeletionStepProof
	decoder := json.NewDecoder(bytes.NewReader([]byte(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return networkDeletionStepProof{}, ErrNetworkDeletionWorker
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return networkDeletionStepProof{}, ErrNetworkDeletionWorker
	}
	if proof.Failed < 0 || proof.Failed > 16 {
		return networkDeletionStepProof{}, ErrNetworkDeletionWorker
	}
	if !proof.Changed {
		if proof != (networkDeletionStepProof{Failed: proof.Failed}) {
			return networkDeletionStepProof{}, ErrNetworkDeletionWorker
		}
		return proof, nil
	}
	previous, err := hex.DecodeString(proof.PreviousHash)
	networkID, networkErr := publicid.Parse(proof.NetworkID)
	if err != nil || networkErr != nil || len(previous) != sha256.Size || proof.ChangeID != change.String() ||
		networkID.String() != proof.NetworkID || proof.AggregateVersion <= 0 || proof.StreamID <= 0 ||
		proof.Sequence <= 0 || proof.NetworkRevision <= 0 ||
		(proof.Action == "network.delete_completed") != proof.Completed ||
		(proof.Action != "network.delete_completed" && proof.Action != "network.devices_revoked") ||
		!json.Valid([]byte(proof.AuditPayload)) || !json.Valid([]byte(proof.OutboxPayload)) ||
		len(proof.AuditPayload) > 16384 || len(proof.OutboxPayload) > 16384 {
		return networkDeletionStepProof{}, ErrNetworkDeletionWorker
	}
	return proof, nil
}

// hashNetworkDeletionStep binds the event to fresh event and outbox ids; the
// system actor and correlation are zero, as in other reconcilers.
func hashNetworkDeletionStep(proof networkDeletionStepProof, change, eventID, outboxID publicid.ID) ([]byte, error) {
	previous, err := hex.DecodeString(proof.PreviousHash)
	if err != nil || len(previous) != sha256.Size {
		return nil, ErrNetworkDeletionWorker
	}
	networkID, err := publicid.Parse(proof.NetworkID)
	if err != nil {
		return nil, ErrNetworkDeletionWorker
	}
	hash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: [32]byte(previous), EventID: eventID, ChangeID: change,
		AggregateKind: "network", AggregateID: networkID, AggregateVersion: proof.AggregateVersion,
		NetworkRevision: proof.NetworkRevision, Action: proof.Action, Permission: "system.reconcile",
		AuditPayloadHash:  sha256.Sum256([]byte(proof.AuditPayload)),
		OutboxEventClass:  "network.revision.advanced",
		OutboxPayloadHash: sha256.Sum256([]byte(proof.OutboxPayload)),
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		StreamID      int64  `json:"stream_id"`
		Sequence      int64  `json:"sequence"`
		PreviousHash  string `json:"previous_hash"`
		AuditPayload  string `json:"audit_payload"`
		OutboxPayload string `json:"outbox_payload"`
		EventID       string `json:"event_id"`
		OutboxID      string `json:"outbox_id"`
		EventHash     string `json:"event_hash"`
	}{proof.StreamID, proof.Sequence, proof.PreviousHash, proof.AuditPayload, proof.OutboxPayload,
		eventID.String(), outboxID.String(), hex.EncodeToString(hash[:])})
}

// Step revokes up to batch Devices of the oldest unfinished deletion, or
// finishes it, with one evidence record, in one transaction. An unknown
// commit outcome is reported, never retried here: the next step re-reads.
func (store *NetworkDeletionWorkerStore) Step(ctx context.Context, installation deployment.ID,
	batch int) (_ deletion.Step, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || batch < 1 || batch > 2000 {
		return deletion.Step{}, deletion.ErrInvalid
	}
	var ids [3]publicid.ID
	for index := range ids {
		id, err := freshPublicID()
		if err != nil {
			return deletion.Step{}, errors.Join(ErrNetworkDeletionWorker, err)
		}
		ids[index] = id
	}
	change, eventID, outboxID := ids[0], ids[1], ids[2]
	transaction, beginErr := store.database.Begin(ctx, false)
	committed := false
	if transaction != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
			}
		}()
	}
	if beginErr != nil || transaction == nil {
		return deletion.Step{}, errors.Join(ErrNetworkDeletionWorker, beginErr)
	}
	// The statement and idle bounds come from the step's deadline.
	deadline := 30 * time.Second
	if until, ok := ctx.Deadline(); ok {
		deadline = max(time.Until(until), time.Second)
	}
	bound := strconv.FormatInt(deadline.Milliseconds(), 10)
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, bound, "1000", bound); err != nil {
		return deletion.Step{}, errors.Join(ErrNetworkDeletionWorker, err)
	}
	var encoded string
	if err := transaction.QueryRow(ctx, prepareNetworkDeletionStepSQL, installation.String(), change.String(),
		batch).Scan(&encoded); err != nil {
		return deletion.Step{}, errors.Join(ErrNetworkDeletionWorker, err)
	}
	proof, err := decodeNetworkDeletionStepProof(encoded, change)
	if err != nil {
		return deletion.Step{}, err
	}
	if !proof.Changed {
		// A failed deletion's back-off (claimed_until) is kept; nothing
		// else changed.
		if proof.Failed > 0 {
			if err := transaction.Commit(ctx); err != nil {
				committed = true
				return deletion.Step{}, errors.Join(ErrNetworkDeletionWorker, err)
			}
			committed = true
		}
		return deletion.Step{Failed: proof.Failed}, nil
	}
	var audited networkDeletionStepAudit
	if err := json.Unmarshal([]byte(proof.AuditPayload), &audited); err != nil || audited.DevicesRevoked < 0 {
		return deletion.Step{}, ErrNetworkDeletionWorker
	}
	event, err := hashNetworkDeletionStep(proof, change, eventID, outboxID)
	if err != nil {
		return deletion.Step{}, errors.Join(ErrNetworkDeletionWorker, err)
	}
	var sequence int64
	if err := transaction.QueryRow(ctx, finalizeNetworkDeletionStepSQL, change.String(), event).Scan(&sequence); err != nil {
		return deletion.Step{}, errors.Join(ErrNetworkDeletionWorker, err)
	}
	if sequence != proof.Sequence {
		return deletion.Step{}, ErrNetworkDeletionWorker
	}
	if err := transaction.Commit(ctx); err != nil {
		committed = true
		return deletion.Step{}, errors.Join(ErrNetworkDeletionWorker, err)
	}
	committed = true
	return deletion.Step{Changed: true, Completed: proof.Completed, Revoked: audited.DevicesRevoked,
		Failed: proof.Failed}, nil
}

// Lag reads the backlog in a read-only transaction.
func (store *NetworkDeletionWorkerStore) Lag(ctx context.Context, installation deployment.ID) (_ deletion.Lag,
	resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() {
		return deletion.Lag{}, deletion.ErrInvalid
	}
	transaction, beginErr := store.database.Begin(ctx, true)
	if transaction != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction)) }()
	}
	if beginErr != nil || transaction == nil {
		return deletion.Lag{}, errors.Join(ErrNetworkDeletionWorker, beginErr)
	}
	var pending int64
	var oldest *time.Time
	var now time.Time
	if err := transaction.QueryRow(ctx, networkDeletionLagSQL, installation.String()).Scan(&pending, &oldest); err != nil {
		return deletion.Lag{}, errors.Join(ErrNetworkDeletionWorker, err)
	}
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.transaction_timestamp()`).Scan(&now); err != nil {
		return deletion.Lag{}, errors.Join(ErrNetworkDeletionWorker, err)
	}
	lag := deletion.Lag{Pending: pending}
	if oldest != nil && now.After(*oldest) {
		lag.Oldest = now.Sub(*oldest)
	}
	return lag, nil
}

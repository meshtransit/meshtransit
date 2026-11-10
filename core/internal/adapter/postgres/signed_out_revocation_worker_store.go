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
	prepareSignedOutRevocationStepSQL  = `SELECT mesh_ops.prepare_signed_out_revocation_step_v1($1::UUID,$2::UUID)::TEXT`
	finalizeSignedOutRevocationStepSQL = `SELECT mesh_ops.finalize_signed_out_revocation_step_v1($1::UUID,$2::JSONB)`
	signedOutRevocationLagSQL          = `SELECT pending, oldest_due_at FROM mesh_ops.signed_out_revocation_lag_v1($1::UUID)`
	signedOutRevocationAction          = "device.revoked"
)

// ErrSignedOutRevocationWorker reports a failed or uncertain step.
var ErrSignedOutRevocationWorker = errors.New("postgres signed-out Device revocation worker failed")

// SignedOutRevocationWorkerStore removes Devices signed out past their hold
// (schema 284) on the worker pool: one Device a step, its evidence hashed
// here, in one transaction. It runs in the Network deletion worker's loop
// (deletion.Worker), so a step that revokes a Device reports one revoked.
type SignedOutRevocationWorkerStore struct{ database outboxDatabase }

var _ deletion.WorkerStore = (*SignedOutRevocationWorkerStore)(nil)

// NewSignedOutRevocationWorkerStore rejects non-worker pools.
func NewSignedOutRevocationWorkerStore(pool *Pool) (*SignedOutRevocationWorkerStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, deletion.ErrInvalid
	}
	return &SignedOutRevocationWorkerStore{database: pool.outboxDatabase}, nil
}

type signedOutRevocationProof struct {
	Changed          bool   `json:"changed"`
	Failed           int    `json:"failed"`
	ChangeID         string `json:"change_id"`
	DeviceID         string `json:"device_id"`
	AggregateVersion int64  `json:"aggregate_version"`
	Action           string `json:"action"`
	StreamID         int64  `json:"stream_id"`
	Sequence         int64  `json:"sequence"`
	PreviousHash     string `json:"previous_hash"`
	NetworkRevision  int64  `json:"network_revision"`
	AuditPayload     string `json:"audit_payload"`
	OutboxPayload    string `json:"outbox_payload"`
}

func decodeSignedOutRevocationProof(encoded string, change publicid.ID) (signedOutRevocationProof, error) {
	if len(encoded) == 0 || len(encoded) > 65536 {
		return signedOutRevocationProof{}, ErrSignedOutRevocationWorker
	}
	var proof signedOutRevocationProof
	decoder := json.NewDecoder(bytes.NewReader([]byte(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return signedOutRevocationProof{}, ErrSignedOutRevocationWorker
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return signedOutRevocationProof{}, ErrSignedOutRevocationWorker
	}
	if proof.Failed < 0 || proof.Failed > 16 {
		return signedOutRevocationProof{}, ErrSignedOutRevocationWorker
	}
	if !proof.Changed {
		if proof != (signedOutRevocationProof{Failed: proof.Failed}) {
			return signedOutRevocationProof{}, ErrSignedOutRevocationWorker
		}
		return proof, nil
	}
	previous, err := hex.DecodeString(proof.PreviousHash)
	deviceID, deviceErr := publicid.Parse(proof.DeviceID)
	if err != nil || deviceErr != nil || len(previous) != sha256.Size || proof.ChangeID != change.String() ||
		deviceID.String() != proof.DeviceID || proof.AggregateVersion <= 0 || proof.StreamID <= 0 ||
		proof.Sequence <= 0 || proof.NetworkRevision <= 0 || proof.Action != signedOutRevocationAction ||
		!json.Valid([]byte(proof.AuditPayload)) || !json.Valid([]byte(proof.OutboxPayload)) ||
		len(proof.AuditPayload) > 16384 || len(proof.OutboxPayload) > 16384 {
		return signedOutRevocationProof{}, ErrSignedOutRevocationWorker
	}
	return proof, nil
}

// hashSignedOutRevocationStep binds the event to fresh event and outbox ids;
// the system actor and correlation are zero, as in other reconcilers.
func hashSignedOutRevocationStep(proof signedOutRevocationProof, change, eventID, outboxID publicid.ID) ([]byte,
	error) {
	previous, err := hex.DecodeString(proof.PreviousHash)
	if err != nil || len(previous) != sha256.Size {
		return nil, ErrSignedOutRevocationWorker
	}
	deviceID, err := publicid.Parse(proof.DeviceID)
	if err != nil {
		return nil, ErrSignedOutRevocationWorker
	}
	hash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: [32]byte(previous), EventID: eventID, ChangeID: change,
		AggregateKind: "device", AggregateID: deviceID, AggregateVersion: proof.AggregateVersion,
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

// Step revokes one Device signed out past its hold, with one evidence
// record, in one transaction; batch is ignored. An unknown commit outcome
// is reported, never retried here: the next step re-reads.
func (store *SignedOutRevocationWorkerStore) Step(ctx context.Context, installation deployment.ID,
	_ int) (_ deletion.Step, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() {
		return deletion.Step{}, deletion.ErrInvalid
	}
	var ids [3]publicid.ID
	for index := range ids {
		id, err := freshPublicID()
		if err != nil {
			return deletion.Step{}, errors.Join(ErrSignedOutRevocationWorker, err)
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
		return deletion.Step{}, errors.Join(ErrSignedOutRevocationWorker, beginErr)
	}
	deadline := 30 * time.Second
	if until, ok := ctx.Deadline(); ok {
		deadline = max(time.Until(until), time.Second)
	}
	bound := strconv.FormatInt(deadline.Milliseconds(), 10)
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, bound, "1000", bound); err != nil {
		return deletion.Step{}, errors.Join(ErrSignedOutRevocationWorker, err)
	}
	var encoded string
	if err := transaction.QueryRow(ctx, prepareSignedOutRevocationStepSQL, installation.String(),
		change.String()).Scan(&encoded); err != nil {
		return deletion.Step{}, errors.Join(ErrSignedOutRevocationWorker, err)
	}
	proof, err := decodeSignedOutRevocationProof(encoded, change)
	if err != nil {
		return deletion.Step{}, err
	}
	if !proof.Changed {
		// A failed Device's back-off is kept; nothing else changed.
		if proof.Failed > 0 {
			if err := transaction.Commit(ctx); err != nil {
				committed = true
				return deletion.Step{}, errors.Join(ErrSignedOutRevocationWorker, err)
			}
			committed = true
		}
		return deletion.Step{Failed: proof.Failed}, nil
	}
	event, err := hashSignedOutRevocationStep(proof, change, eventID, outboxID)
	if err != nil {
		return deletion.Step{}, errors.Join(ErrSignedOutRevocationWorker, err)
	}
	var sequence int64
	if err := transaction.QueryRow(ctx, finalizeSignedOutRevocationStepSQL, change.String(), event).
		Scan(&sequence); err != nil {
		return deletion.Step{}, errors.Join(ErrSignedOutRevocationWorker, err)
	}
	if sequence != proof.Sequence {
		return deletion.Step{}, ErrSignedOutRevocationWorker
	}
	if err := transaction.Commit(ctx); err != nil {
		committed = true
		return deletion.Step{}, errors.Join(ErrSignedOutRevocationWorker, err)
	}
	committed = true
	return deletion.Step{Changed: true, Revoked: 1, Failed: proof.Failed}, nil
}

// Lag reads how many Devices are past their hold, and since when.
func (store *SignedOutRevocationWorkerStore) Lag(ctx context.Context, installation deployment.ID) (_ deletion.Lag,
	resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() {
		return deletion.Lag{}, deletion.ErrInvalid
	}
	transaction, beginErr := store.database.Begin(ctx, true)
	if transaction != nil {
		defer func() { resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction)) }()
	}
	if beginErr != nil || transaction == nil {
		return deletion.Lag{}, errors.Join(ErrSignedOutRevocationWorker, beginErr)
	}
	var pending int64
	var oldest *time.Time
	var now time.Time
	if err := transaction.QueryRow(ctx, signedOutRevocationLagSQL, installation.String()).
		Scan(&pending, &oldest); err != nil {
		return deletion.Lag{}, errors.Join(ErrSignedOutRevocationWorker, err)
	}
	if err := transaction.QueryRow(ctx, `SELECT pg_catalog.transaction_timestamp()`).Scan(&now); err != nil {
		return deletion.Lag{}, errors.Join(ErrSignedOutRevocationWorker, err)
	}
	lag := deletion.Lag{Pending: pending}
	if oldest != nil && now.After(*oldest) {
		lag.Oldest = now.Sub(*oldest)
	}
	return lag, nil
}

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/captivewindow"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

var (
	// ErrInvalidCaptiveWindowStore reports unsafe construction or input.
	ErrInvalidCaptiveWindowStore = errors.New("invalid postgres captive window store")
	// ErrCaptiveWindowStore classifies a failed record.
	ErrCaptiveWindowStore = errors.New("postgres captive window store")
)

const (
	recordDeviceCaptiveWindowSQL = `SELECT mesh_ops.record_device_captive_window_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::TEXT,$5::TIMESTAMPTZ,$6::TIMESTAMPTZ,$7::TEXT,$8::UUID,$9::UUID)::TEXT`
	appendDeviceCaptiveWindowEvidenceSQL = `SELECT mesh_ops.append_device_captive_window_evidence_v1(
    $1::UUID,$2::BIGINT,$3::BIGINT,$4::BYTEA,$5::BYTEA,$6::UUID,$7::UUID,$8::JSONB)`
	captiveWindowAction         = "device.captive_window"
	captiveWindowAggregateKind  = "device_captive_window"
	captiveWindowMaximumPayload = 4096
)

// CaptiveWindowStore records the captive portal windows Devices report,
// each with its sealed audit event, through the runtime pool of the control
// plane (schema 212).
type CaptiveWindowStore struct{ database outboxDatabase }

var _ captivewindow.Recorder = (*CaptiveWindowStore)(nil)

// NewCaptiveWindowStore accepts the runtime pool only.
func NewCaptiveWindowStore(pool *Pool) (*CaptiveWindowStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.outboxDatabase == nil {
		return nil, ErrInvalidCaptiveWindowStore
	}
	return &CaptiveWindowStore{database: pool.outboxDatabase}, nil
}

// Record records one window device of scope reported, once.
func (store *CaptiveWindowStore) Record(ctx context.Context, scope network.Scope, device node.ID,
	window captivewindow.Window) (captivewindow.Outcome, error) {
	if ctx == nil || store == nil || store.database == nil || !scope.IsValid() || !device.IsValid() ||
		window.Validate(time.Now()) != nil {
		return 0, ErrInvalidCaptiveWindowStore
	}
	return retryReadConflict(ctx, func() (captivewindow.Outcome, error) {
		return store.recordOnce(ctx, scope, device, window)
	})
}

func (store *CaptiveWindowStore) recordOnce(ctx context.Context, scope network.Scope, device node.ID,
	window captivewindow.Window) (outcome captivewindow.Outcome, resultErr error) {
	var ids [4]publicid.ID
	for index := range ids {
		id, err := freshPublicID()
		if err != nil {
			return 0, errors.Join(ErrCaptiveWindowStore, err)
		}
		ids[index] = id
	}
	eventID, change, auditEventID, outboxID := ids[0], ids[1], ids[2], ids[3]
	if err := ctx.Err(); err != nil {
		return 0, errors.Join(ErrCaptiveWindowStore, err)
	}
	transaction, err := store.database.Begin(ctx, false)
	if err != nil || transaction == nil {
		return 0, errors.Join(ErrCaptiveWindowStore, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
		}
	}()
	timeout := postgresTimeout(10 * time.Second)
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, timeout, "2000", timeout); err != nil {
		return 0, errors.Join(ErrCaptiveWindowStore, err)
	}
	var encoded string
	if err := transaction.QueryRow(ctx, recordDeviceCaptiveWindowSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String(), device.String(), window.ID, window.OpenedAt.UTC(), window.ClosedAt.UTC(),
		string(window.End), eventID.String(), change.String()).Scan(&encoded); err != nil {
		return 0, errors.Join(ErrCaptiveWindowStore, err)
	}
	proof, err := decodeCaptiveWindowProof(encoded, eventID)
	if err != nil {
		return 0, err
	}
	switch {
	case proof.Busy:
		return captivewindow.OutcomeBusy, nil
	case proof.Limited:
		return captivewindow.OutcomeLimited, nil
	case !proof.Recorded:
		return captivewindow.OutcomeKnown, nil
	}
	hash, err := hashCaptiveWindowEvent(proof, change, auditEventID)
	if err != nil {
		return 0, errors.Join(ErrCaptiveWindowStore, err)
	}
	previous, _ := hex.DecodeString(proof.PreviousHash)
	var sequence int64
	if err := transaction.QueryRow(ctx, appendDeviceCaptiveWindowEvidenceSQL, eventID.String(), proof.StreamID,
		proof.Sequence, previous, hash[:], auditEventID.String(), outboxID.String(), proof.Payload,
	).Scan(&sequence); err != nil {
		return 0, errors.Join(ErrCaptiveWindowStore, err)
	}
	if sequence != proof.Sequence {
		return 0, ErrCaptiveWindowStore
	}
	if err := transaction.Commit(ctx); err != nil {
		committed = true
		return 0, errors.Join(ErrCaptiveWindowStore, err)
	}
	committed = true
	return captivewindow.OutcomeAudited, nil
}

type captiveWindowProof struct {
	Recorded        bool   `json:"recorded"`
	Busy            bool   `json:"busy"`
	Limited         bool   `json:"limited"`
	EventID         string `json:"event_id"`
	NetworkRevision int64  `json:"network_revision"`
	SemanticHash    string `json:"semantic_hash"`
	StreamID        int64  `json:"stream_id"`
	Sequence        int64  `json:"sequence"`
	PreviousHash    string `json:"previous_hash"`
	Payload         string `json:"payload"`
}

func decodeCaptiveWindowProof(encoded string, event publicid.ID) (captiveWindowProof, error) {
	var proof captiveWindowProof
	if err := decodeStrictJSON(encoded, 16384, &proof); err != nil {
		return captiveWindowProof{}, ErrCaptiveWindowStore
	}
	if !proof.Recorded {
		if (proof.Busy && proof.Limited) || proof.EventID != "" || proof.Payload != "" || proof.StreamID != 0 {
			return captiveWindowProof{}, ErrCaptiveWindowStore
		}
		return proof, nil
	}
	semantic, semanticErr := hex.DecodeString(proof.SemanticHash)
	previous, previousErr := hex.DecodeString(proof.PreviousHash)
	payloadHash := sha256.Sum256([]byte(proof.Payload))
	if proof.Busy || proof.Limited || proof.EventID != event.String() || proof.NetworkRevision < 1 ||
		semanticErr != nil || len(semantic) != sha256.Size || previousErr != nil || len(previous) != sha256.Size ||
		proof.StreamID < 1 || proof.Sequence < 1 || len(proof.Payload) == 0 ||
		len(proof.Payload) > captiveWindowMaximumPayload || !json.Valid([]byte(proof.Payload)) ||
		[sha256.Size]byte(semantic) != payloadHash {
		return captiveWindowProof{}, ErrCaptiveWindowStore
	}
	return proof, nil
}

// hashCaptiveWindowEvent binds the event to the stream head the database
// returned. The system actor and correlation are zero, as for enforcement
// evidence; the semantic hash is the payload's.
func hashCaptiveWindowEvent(proof captiveWindowProof, change, event publicid.ID) ([sha256.Size]byte, error) {
	previous, err := hex.DecodeString(proof.PreviousHash)
	if err != nil || len(previous) != sha256.Size {
		return [sha256.Size]byte{}, ErrCaptiveWindowStore
	}
	aggregate, err := publicid.Parse(proof.EventID)
	if err != nil {
		return [sha256.Size]byte{}, ErrCaptiveWindowStore
	}
	payloadHash := sha256.Sum256([]byte(proof.Payload))
	return audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: [sha256.Size]byte(previous), EventID: event, ChangeID: change,
		AggregateKind: captiveWindowAggregateKind, AggregateID: aggregate, AggregateVersion: 1,
		NetworkRevision: proof.NetworkRevision, Action: captiveWindowAction, Permission: enforcementLedgerPermission,
		AfterSemanticHash: payloadHash, AuditPayloadHash: payloadHash,
		OutboxEventClass: captiveWindowAction, OutboxPayloadHash: payloadHash,
	})
}

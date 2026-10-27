package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/shared/kubejoin"
)

var (
	// ErrInvalidKubernetesGatewayKeyEventStore reports unsafe construction
	// or input.
	ErrInvalidKubernetesGatewayKeyEventStore = errors.New("invalid postgres Kubernetes gateway key event store")
	// ErrKubernetesGatewayKeyEventStore classifies a failed record.
	ErrKubernetesGatewayKeyEventStore = errors.New("postgres Kubernetes gateway key event store")
)

const (
	recordKubernetesGatewayKeyEventSQL = `SELECT mesh_ops.record_kubernetes_gateway_key_event_v3(
    $1::BYTEA,$2::TEXT,$3::INTEGER,$4::UUID,$5::UUID,$6::TEXT)::TEXT`
	appendKubernetesGatewayKeyEventEvidenceSQL = `SELECT mesh_ops.append_kubernetes_gateway_key_event_evidence_v1(
    $1::UUID,$2::BIGINT,$3::BIGINT,$4::BYTEA,$5::BYTEA,$6::UUID,$7::UUID,$8::JSONB)`
	gatewayKeyEventAggregateKind  = "kubernetes_gateway_key_event"
	gatewayKeyEventMaximumPayload = 4096
	// A report waits briefly for a lock, then gives way: it runs beside
	// handshakes and real changes to the Network's audit stream.
	gatewayKeyEventLockTimeout      = 200 * time.Millisecond
	gatewayKeyEventStatementTimeout = 2 * time.Second
)

// KubernetesGatewayKeyEventStore records a gateway's stale or contested
// keys and its refused rotation tokens, each with its sealed audit event,
// through the runtime pool of the control plane (schemas 229, 233).
type KubernetesGatewayKeyEventStore struct{ database outboxDatabase }

// NewKubernetesGatewayKeyEventStore accepts the runtime pool only.
func NewKubernetesGatewayKeyEventStore(pool *Pool) (*KubernetesGatewayKeyEventStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.outboxDatabase == nil {
		return nil, ErrInvalidKubernetesGatewayKeyEventStore
	}
	return &KubernetesGatewayKeyEventStore{database: pool.outboxDatabase}, nil
}

// Record records one report of the gateway key whose node-domain
// fingerprint is machine, once per key, reason and window. suppressed is
// the number of reports folded into it. It never retries: a report that
// meets a lock is busy.
func (store *KubernetesGatewayKeyEventStore) Record(ctx context.Context, machine [32]byte,
	reason kubecluster.KeyEventReason, suppressed int, keyID string) (outcome kubecluster.KeyEventOutcome,
	resultErr error) {
	if ctx == nil || store == nil || store.database == nil || machine == ([32]byte{}) || !reason.IsKnown() ||
		suppressed < 0 || suppressed > kubecluster.MaximumSuppressedReports ||
		keyID != "" && (reason != kubecluster.KeyEventTokenUnknownKey || !kubejoin.ValidKeyID(keyID)) {
		return 0, ErrInvalidKubernetesGatewayKeyEventStore
	}
	// Schema 235: a kid only with a key the trust lacks.
	var tokenKeyID any
	if keyID != "" {
		tokenKeyID = keyID
	}
	var ids [4]publicid.ID
	for index := range ids {
		id, err := freshPublicID()
		if err != nil {
			return 0, errors.Join(ErrKubernetesGatewayKeyEventStore, err)
		}
		ids[index] = id
	}
	eventID, change, auditEventID, outboxID := ids[0], ids[1], ids[2], ids[3]
	transaction, err := store.database.Begin(ctx, false)
	if err != nil || transaction == nil {
		return 0, errors.Join(ErrKubernetesGatewayKeyEventStore, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
		}
	}()
	statement := postgresTimeout(gatewayKeyEventStatementTimeout)
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, statement,
		postgresTimeout(gatewayKeyEventLockTimeout), statement); err != nil {
		return 0, errors.Join(ErrKubernetesGatewayKeyEventStore, err)
	}
	var encoded string
	if err := transaction.QueryRow(ctx, recordKubernetesGatewayKeyEventSQL, machine[:], string(reason), suppressed,
		eventID.String(), change.String(), tokenKeyID).Scan(&encoded); err != nil {
		return gatewayKeyEventBusy(err)
	}
	proof, err := decodeGatewayKeyEventProof(encoded, eventID, reason)
	if err != nil {
		return 0, err
	}
	switch proof.Outcome {
	case "unknown":
		return kubecluster.KeyEventNotGateway, nil
	case "busy":
		return kubecluster.KeyEventBusy, nil
	case "limited":
		return kubecluster.KeyEventLimited, nil
	}
	hash, previous, err := hashGatewayKeyEvent(proof, change, auditEventID)
	if err != nil {
		return 0, err
	}
	var sequence int64
	if err := transaction.QueryRow(ctx, appendKubernetesGatewayKeyEventEvidenceSQL, eventID.String(),
		proof.StreamID, proof.Sequence, previous, hash[:], auditEventID.String(), outboxID.String(), proof.Payload,
	).Scan(&sequence); err != nil {
		return gatewayKeyEventBusy(err)
	}
	if sequence != proof.Sequence {
		return 0, ErrKubernetesGatewayKeyEventStore
	}
	if err := transaction.Commit(ctx); err != nil {
		committed = true
		return 0, errors.Join(ErrKubernetesGatewayKeyEventStore, err)
	}
	committed = true
	return kubecluster.KeyEventRecorded, nil
}

// gatewayKeyEventBusy answers a lock that timed out, or a stream head that
// moved under a real change (40001), as busy; anything else is a failure.
func gatewayKeyEventBusy(err error) (kubecluster.KeyEventOutcome, error) {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && (pgError.Code == "55P03" || pgError.Code == "40001" || pgError.Code == "40P01") {
		return kubecluster.KeyEventBusy, nil
	}
	return 0, errors.Join(ErrKubernetesGatewayKeyEventStore, err)
}

type gatewayKeyEventProof struct {
	Outcome         string `json:"outcome"`
	Action          string `json:"action"`
	EventID         string `json:"event_id"`
	NetworkRevision int64  `json:"network_revision"`
	SemanticHash    string `json:"semantic_hash"`
	StreamID        int64  `json:"stream_id"`
	Sequence        int64  `json:"sequence"`
	PreviousHash    string `json:"previous_hash"`
	Payload         string `json:"payload"`
}

func decodeGatewayKeyEventProof(encoded string, event publicid.ID,
	reason kubecluster.KeyEventReason) (gatewayKeyEventProof, error) {
	var proof gatewayKeyEventProof
	if err := decodeStrictJSON(encoded, 16384, &proof); err != nil {
		return gatewayKeyEventProof{}, ErrKubernetesGatewayKeyEventStore
	}
	switch proof.Outcome {
	case "unknown", "busy", "limited":
		if proof != (gatewayKeyEventProof{Outcome: proof.Outcome}) {
			return gatewayKeyEventProof{}, ErrKubernetesGatewayKeyEventStore
		}
		return proof, nil
	case "recorded":
	default:
		return gatewayKeyEventProof{}, ErrKubernetesGatewayKeyEventStore
	}
	semantic, semanticErr := hex.DecodeString(proof.SemanticHash)
	previous, previousErr := hex.DecodeString(proof.PreviousHash)
	payloadHash := sha256.Sum256([]byte(proof.Payload))
	if proof.Action != reason.Action() || proof.EventID != event.String() ||
		proof.NetworkRevision < 1 || semanticErr != nil || len(semantic) != sha256.Size ||
		previousErr != nil || len(previous) != sha256.Size || proof.StreamID < 1 || proof.Sequence < 1 ||
		len(proof.Payload) == 0 || len(proof.Payload) > gatewayKeyEventMaximumPayload ||
		!json.Valid([]byte(proof.Payload)) || [sha256.Size]byte(semantic) != payloadHash {
		return gatewayKeyEventProof{}, ErrKubernetesGatewayKeyEventStore
	}
	return proof, nil
}

// hashGatewayKeyEvent binds the event to the stream head the database
// returned. The system actor and correlation are zero, as for enforcement
// evidence; the semantic hash is the payload's.
func hashGatewayKeyEvent(proof gatewayKeyEventProof, change, event publicid.ID) ([sha256.Size]byte, []byte,
	error) {
	previous, err := hex.DecodeString(proof.PreviousHash)
	if err != nil || len(previous) != sha256.Size {
		return [sha256.Size]byte{}, nil, ErrKubernetesGatewayKeyEventStore
	}
	aggregate, err := publicid.Parse(proof.EventID)
	if err != nil {
		return [sha256.Size]byte{}, nil, ErrKubernetesGatewayKeyEventStore
	}
	payloadHash := sha256.Sum256([]byte(proof.Payload))
	hash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: [sha256.Size]byte(previous), EventID: event, ChangeID: change,
		AggregateKind: gatewayKeyEventAggregateKind, AggregateID: aggregate, AggregateVersion: 1,
		NetworkRevision: proof.NetworkRevision, Action: proof.Action, Permission: enforcementLedgerPermission,
		AfterSemanticHash: payloadHash, AuditPayloadHash: payloadHash,
		OutboxEventClass: proof.Action, OutboxPayloadHash: payloadHash,
	})
	return hash, previous, err
}

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

var (
	// ErrInvalidKubernetesGatewayGroupReportStore reports unsafe
	// construction or input.
	ErrInvalidKubernetesGatewayGroupReportStore = errors.New("invalid postgres Kubernetes gateway group report store")
	// ErrKubernetesGatewayGroupReportStore classifies a failed record.
	ErrKubernetesGatewayGroupReportStore = errors.New("postgres Kubernetes gateway group report store")
)

const (
	recordKubernetesGatewayGroupReportSQL = `SELECT mesh_ops.record_kubernetes_gateway_group_report_v1(
    $1::BYTEA,$2::BYTEA,$3::BOOLEAN,$4::JSONB,$5::BOOLEAN,$6::TIMESTAMPTZ,$7::TIMESTAMPTZ,$8::UUID,$9::UUID)::TEXT`
	appendKubernetesGatewayGroupEventEvidenceSQL = `SELECT mesh_ops.append_kubernetes_gateway_group_event_evidence_v1(
    $1::UUID,$2::BIGINT,$3::BIGINT,$4::BYTEA,$5::BYTEA,$6::UUID,$7::UUID,$8::JSONB)`
	gatewayGroupReportsGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(pg_catalog.to_regprocedure(
    'mesh_ops.record_kubernetes_gateway_group_report_v1(bytea,bytea,boolean,jsonb,boolean,timestamp with time zone,timestamp with time zone,uuid,uuid)'),
    'EXECUTE'), FALSE)
  AND COALESCE(pg_catalog.has_function_privilege(pg_catalog.to_regprocedure(
    'mesh_ops.append_kubernetes_gateway_group_event_evidence_v1(uuid,bigint,bigint,bytea,bytea,uuid,uuid,jsonb)'),
    'EXECUTE'), FALSE)`
	gatewayGroupEventAggregateKind  = "kubernetes_gateway_group_event"
	gatewayGroupDisabledAction      = "kubernetes_gateway.group_disabled"
	gatewayGroupEventMaximumPayload = 8192
	// A report takes the Device's lock at once or gives way to the
	// handshake holding it (busy); other locks it waits for briefly.
	gatewayGroupReportLockTimeout      = 500 * time.Millisecond
	gatewayGroupReportStatementTimeout = 3 * time.Second
)

// GatewayGroupReportOutcome is what recording a report did.
type GatewayGroupReportOutcome int

const (
	// GatewayGroupReportStored kept the report.
	GatewayGroupReportStored GatewayGroupReportOutcome = iota + 1
	// GatewayGroupReportAudited kept it and audited the groups it turned off.
	GatewayGroupReportAudited
	// GatewayGroupReportNotGateway found no gateway Device holding the keys.
	GatewayGroupReportNotGateway
	// GatewayGroupReportBusy met a lock; nothing was kept.
	GatewayGroupReportBusy
)

// KubernetesGatewayGroupReportStore keeps each gateway Device's latest group
// report and audits the groups a report turns off, through the runtime pool
// of the control plane (schema 254).
type KubernetesGatewayGroupReportStore struct{ database outboxDatabase }

// NewKubernetesGatewayGroupReportStore accepts the runtime pool only.
func NewKubernetesGatewayGroupReportStore(pool *Pool) (*KubernetesGatewayGroupReportStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.outboxDatabase == nil {
		return nil, ErrInvalidKubernetesGatewayGroupReportStore
	}
	return &KubernetesGatewayGroupReportStore{database: pool.outboxDatabase}, nil
}

// Granted reports whether the runtime role may record reports (schema 254).
func (store *KubernetesGatewayGroupReportStore) Granted(ctx context.Context) (bool, error) {
	if ctx == nil || store == nil || store.database == nil {
		return false, ErrInvalidKubernetesGatewayGroupReportStore
	}
	var granted bool
	if err := store.database.QueryRow(ctx, gatewayGroupReportsGrantedSQL).Scan(&granted); err != nil {
		return false, errors.Join(ErrKubernetesGatewayGroupReportStore, err)
	}
	return granted, nil
}

// Record keeps report for the gateway Device holding machine (its
// node-domain fingerprint) and nodeKey now. It never retries: a report that
// meets a lock is busy.
func (store *KubernetesGatewayGroupReportStore) Record(ctx context.Context, machine [32]byte, nodeKey []byte,
	report kubecluster.GatewayGroupReport) (outcome GatewayGroupReportOutcome, resultErr error) {
	groups, valid := gatewayGroupReportJSON(report)
	if ctx == nil || store == nil || store.database == nil || machine == ([32]byte{}) || len(nodeKey) != 32 ||
		!valid || report.ReceivedAt.IsZero() {
		return 0, ErrInvalidKubernetesGatewayGroupReportStore
	}
	var checkedAt any
	if !report.CheckedAt.IsZero() {
		checkedAt = report.CheckedAt.UTC()
	}
	var ids [4]publicid.ID
	for index := range ids {
		id, err := freshPublicID()
		if err != nil {
			return 0, errors.Join(ErrKubernetesGatewayGroupReportStore, err)
		}
		ids[index] = id
	}
	eventID, change, auditEventID, outboxID := ids[0], ids[1], ids[2], ids[3]
	transaction, err := store.database.Begin(ctx, false)
	if err != nil || transaction == nil {
		return 0, errors.Join(ErrKubernetesGatewayGroupReportStore, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
		}
	}()
	statement := postgresTimeout(gatewayGroupReportStatementTimeout)
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, statement,
		postgresTimeout(gatewayGroupReportLockTimeout), statement); err != nil {
		return 0, errors.Join(ErrKubernetesGatewayGroupReportStore, err)
	}
	var encoded string
	if err := transaction.QueryRow(ctx, recordKubernetesGatewayGroupReportSQL, machine[:], nodeKey,
		report.Supported, groups, report.Truncated, checkedAt, report.ReceivedAt.UTC(), eventID.String(),
		change.String(),
	).Scan(&encoded); err != nil {
		return gatewayGroupReportBusy(err)
	}
	proof, err := decodeGatewayGroupReportProof(encoded, eventID)
	if err != nil {
		return 0, err
	}
	switch proof.Outcome {
	case "unknown":
		return GatewayGroupReportNotGateway, nil
	case "busy":
		return GatewayGroupReportBusy, nil
	case "stored":
		if err := transaction.Commit(ctx); err != nil {
			committed = true
			return 0, errors.Join(ErrKubernetesGatewayGroupReportStore, err)
		}
		committed = true
		return GatewayGroupReportStored, nil
	}
	hash, previous, err := hashGatewayEvidence(gatewayGroupEventAggregateKind, proof, change, auditEventID)
	if err != nil {
		return 0, errors.Join(ErrKubernetesGatewayGroupReportStore, err)
	}
	var sequence int64
	if err := transaction.QueryRow(ctx, appendKubernetesGatewayGroupEventEvidenceSQL, eventID.String(),
		proof.StreamID, proof.Sequence, previous, hash[:], auditEventID.String(), outboxID.String(), proof.Payload,
	).Scan(&sequence); err != nil {
		return gatewayGroupReportBusy(err)
	}
	if sequence != proof.Sequence {
		return 0, ErrKubernetesGatewayGroupReportStore
	}
	if err := transaction.Commit(ctx); err != nil {
		committed = true
		return 0, errors.Join(ErrKubernetesGatewayGroupReportStore, err)
	}
	committed = true
	return GatewayGroupReportAudited, nil
}

// gatewayGroupReportJSON is the groups as the database keeps them, and
// whether the report holds together.
func gatewayGroupReportJSON(report kubecluster.GatewayGroupReport) (string, bool) {
	groups := report.Groups
	if groups == nil {
		groups = []kubecluster.GatewayGroupStatus{}
	}
	if !report.Supported && (len(groups) != 0 || report.Truncated || !report.CheckedAt.IsZero()) {
		return "", false
	}
	held := kubecluster.ReplicaGroups{Status: kubecluster.GroupReportCurrent, ReportedAt: time.Unix(1, 0),
		Items: groups}
	encoded, err := json.Marshal(groups)
	return string(encoded), err == nil && kubecluster.ValidReplicaGroups(held)
}

func decodeGatewayGroupReportProof(encoded string, event publicid.ID) (gatewayKeyEventProof, error) {
	var proof gatewayKeyEventProof
	if err := decodeStrictJSON(encoded, 2*gatewayGroupEventMaximumPayload, &proof); err != nil {
		return gatewayKeyEventProof{}, ErrKubernetesGatewayGroupReportStore
	}
	switch proof.Outcome {
	case "unknown", "stored", "busy":
		if proof != (gatewayKeyEventProof{Outcome: proof.Outcome}) {
			return gatewayKeyEventProof{}, ErrKubernetesGatewayGroupReportStore
		}
		return proof, nil
	case "recorded":
	default:
		return gatewayKeyEventProof{}, ErrKubernetesGatewayGroupReportStore
	}
	semantic, semanticErr := hex.DecodeString(proof.SemanticHash)
	previous, previousErr := hex.DecodeString(proof.PreviousHash)
	payloadHash := sha256.Sum256([]byte(proof.Payload))
	if proof.Action != gatewayGroupDisabledAction || proof.EventID != event.String() ||
		proof.NetworkRevision < 1 || semanticErr != nil || len(semantic) != sha256.Size ||
		previousErr != nil || len(previous) != sha256.Size || proof.StreamID < 1 || proof.Sequence < 1 ||
		len(proof.Payload) == 0 || len(proof.Payload) > gatewayGroupEventMaximumPayload ||
		!json.Valid([]byte(proof.Payload)) || [sha256.Size]byte(semantic) != payloadHash {
		return gatewayKeyEventProof{}, ErrKubernetesGatewayGroupReportStore
	}
	return proof, nil
}

// gatewayGroupReportBusy answers a lock that timed out, or a stream head
// that moved, as busy; anything else is a failure.
func gatewayGroupReportBusy(err error) (GatewayGroupReportOutcome, error) {
	if outcome, busyErr := gatewayKeyEventBusy(err); busyErr == nil && outcome == kubecluster.KeyEventBusy {
		return GatewayGroupReportBusy, nil
	}
	return 0, errors.Join(ErrKubernetesGatewayGroupReportStore, err)
}

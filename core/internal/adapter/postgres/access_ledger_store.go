package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph/ledger"
	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

var (
	// ErrInvalidAccessLedger reports unsafe construction or input.
	ErrInvalidAccessLedger = errors.New("invalid postgres access ledger")
	// ErrAccessLedger classifies a failed discovery, record or retention call.
	ErrAccessLedger = errors.New("postgres access ledger")
	// ErrAccessLedgerCommitUnknown forbids retry until state is re-read.
	ErrAccessLedgerCommitUnknown = errors.New("postgres access ledger commit outcome unknown")
)

const (
	listAccessLedgerDueSQL      = `SELECT mesh_ops.list_access_ledger_due_v1($1::UUID,$2::INTEGER)::TEXT`
	recordAccessEdgesSQL        = `SELECT mesh_ops.record_access_edges_v1($1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::UUID)::TEXT`
	appendAccessEdgeEvidenceSQL = `SELECT mesh_ops.append_access_edge_evidence_v1(
    $1::UUID,$2::BIGINT,$3::BIGINT,$4::BYTEA,$5::BYTEA,$6::UUID,$7::UUID,$8::JSONB)`
	pruneAccessLedgerSQL          = `SELECT mesh_ops.prune_access_ledger_v1($1::UUID,$2::INTEGER)`
	repeatableReadTransactionSQL  = `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ`
	accessLedgerAction            = "access_graph.recorded"
	accessLedgerPermission        = "system.reconcile"
	accessLedgerAggregateKind     = "access_edge_snapshot"
	accessLedgerMaximumDueBatch   = 64
	accessLedgerMaximumPruneBatch = 10000
)

// AccessLedgerStore records the access edge ledger through a worker pool
// only. It holds no authority cache, sticky transaction or goroutine.
type AccessLedgerStore struct{ database outboxDatabase }

var (
	_ ledger.Due      = (*AccessLedgerStore)(nil)
	_ ledger.Recorder = (*AccessLedgerStore)(nil)
	_ ledger.Pruner   = (*AccessLedgerStore)(nil)
)

// NewAccessLedgerStore rejects non-worker pools before any effect.
func NewAccessLedgerStore(pool *Pool) (*AccessLedgerStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, ErrInvalidAccessLedger
	}
	return &AccessLedgerStore{database: pool.outboxDatabase}, nil
}

// ListDue reads Networks whose revision is newer than the ledger in one
// read-only transaction.
func (store *AccessLedgerStore) ListDue(ctx context.Context, installation deployment.ID, limit int) (result []network.Scope, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() ||
		limit < 1 || limit > accessLedgerMaximumDueBatch {
		return nil, ErrInvalidAccessLedger
	}
	transaction, err := store.begin(ctx, true, false)
	if err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
			result = nil
		}
	}()
	var encoded string
	if err := transaction.QueryRow(ctx, listAccessLedgerDueSQL, installation.String(), limit).Scan(&encoded); err != nil {
		return nil, errors.Join(ErrAccessLedger, err)
	}
	scopes, err := decodeAccessLedgerDue(encoded, limit)
	if err != nil {
		return nil, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, errors.Join(ErrAccessLedger, err)
	}
	committed = true
	return scopes, nil
}

func decodeAccessLedgerDue(encoded string, limit int) ([]network.Scope, error) {
	var record struct {
		Items []struct {
			WorkspaceID string `json:"workspace_id"`
			NetworkID   string `json:"network_id"`
		} `json:"items"`
	}
	if err := decodeStrictJSON(encoded, 65536, &record); err != nil || record.Items == nil || len(record.Items) > limit {
		return nil, ErrAccessLedger
	}
	scopes := make([]network.Scope, 0, len(record.Items))
	for _, item := range record.Items {
		workspaceID, workspaceErr := workspace.ParseID(item.WorkspaceID)
		networkID, networkErr := network.ParseID(item.NetworkID)
		scope, scopeErr := network.NewScope(workspaceID, networkID)
		if workspaceErr != nil || networkErr != nil || scopeErr != nil {
			return nil, ErrAccessLedger
		}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

// Record computes and diffs the edge set of one Network's current revision
// and, when it changed, seals the snapshot as an audit event, all in one
// REPEATABLE READ transaction. An unknown commit outcome is reported and
// never retried here; the next pass re-reads committed state.
func (store *AccessLedgerStore) Record(ctx context.Context, installation deployment.ID, scope network.Scope) (ledger.Outcome, error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || !scope.IsValid() {
		return ledger.OutcomeUnchanged, ErrInvalidAccessLedger
	}
	// A concurrent writer on the Network stream or cursor fails the snapshot
	// with 40001; each attempt starts a fresh transaction with fresh IDs.
	return retryReadConflict(ctx, func() (ledger.Outcome, error) {
		return store.recordOnce(ctx, installation, scope)
	})
}

func (store *AccessLedgerStore) recordOnce(ctx context.Context, installation deployment.ID, scope network.Scope) (outcome ledger.Outcome, resultErr error) {
	var ids [4]publicid.ID
	for index := range ids {
		id, err := freshPublicID()
		if err != nil {
			return ledger.OutcomeUnchanged, errors.Join(ErrAccessLedger, err)
		}
		ids[index] = id
	}
	snapshotID, change, eventID, outboxID := ids[0], ids[1], ids[2], ids[3]
	transaction, err := store.begin(ctx, false, true)
	if err != nil {
		return ledger.OutcomeUnchanged, err
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
			outcome = ledger.OutcomeUnchanged
		}
	}()
	var encoded string
	if err := transaction.QueryRow(ctx, recordAccessEdgesSQL, installation.String(), scope.WorkspaceID().String(),
		scope.NetworkID().String(), snapshotID.String(), change.String()).Scan(&encoded); err != nil {
		return ledger.OutcomeUnchanged, errors.Join(ErrAccessLedger, err)
	}
	proof, err := decodeAccessLedgerProof(encoded, snapshotID)
	if err != nil {
		return ledger.OutcomeUnchanged, err
	}
	outcome = ledger.OutcomeUnchanged
	switch {
	case proof.Busy:
		outcome = ledger.OutcomeBusy
	case proof.Recorded:
		hash, err := hashAccessLedgerEvent(proof, change, eventID)
		if err != nil {
			return ledger.OutcomeUnchanged, errors.Join(ErrAccessLedger, err)
		}
		previous, _ := hex.DecodeString(proof.PreviousHash)
		var sequence int64
		if err := transaction.QueryRow(ctx, appendAccessEdgeEvidenceSQL, snapshotID.String(), proof.StreamID,
			proof.Sequence, previous, hash[:], eventID.String(), outboxID.String(), proof.Payload,
		).Scan(&sequence); err != nil {
			return ledger.OutcomeUnchanged, errors.Join(ErrAccessLedger, err)
		}
		if sequence != proof.Sequence {
			return ledger.OutcomeUnchanged, ErrAccessLedger
		}
		outcome = ledger.OutcomeRecorded
	}
	if err := ctx.Err(); err != nil {
		return ledger.OutcomeUnchanged, errors.Join(ErrAccessLedger, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return ledger.OutcomeUnchanged, errors.Join(ErrAccessLedger, ErrAccessLedgerCommitUnknown, err)
	}
	committed = true
	return outcome, nil
}

// Prune removes one bounded batch of rows past retention.
func (store *AccessLedgerStore) Prune(ctx context.Context, installation deployment.ID, limit int) (removed int, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() ||
		limit < 1 || limit > accessLedgerMaximumPruneBatch {
		return 0, ErrInvalidAccessLedger
	}
	transaction, err := store.begin(ctx, false, false)
	if err != nil {
		return 0, err
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
			removed = 0
		}
	}()
	if err := transaction.QueryRow(ctx, pruneAccessLedgerSQL, installation.String(), limit).Scan(&removed); err != nil {
		return 0, errors.Join(ErrAccessLedger, err)
	}
	if removed < 0 {
		return 0, ErrAccessLedger
	}
	if err := transaction.Commit(ctx); err != nil {
		return 0, errors.Join(ErrAccessLedger, ErrAccessLedgerCommitUnknown, err)
	}
	committed = true
	return removed, nil
}

func (store *AccessLedgerStore) begin(ctx context.Context, readOnly, repeatable bool) (outboxTransaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrAccessLedger, err)
	}
	transaction, err := store.database.Begin(ctx, readOnly)
	if err != nil {
		return nil, errors.Join(ErrAccessLedger, err)
	}
	if transaction == nil {
		return nil, ErrAccessLedger
	}
	if repeatable {
		if err := transaction.Exec(ctx, repeatableReadTransactionSQL); err != nil {
			return nil, errors.Join(ErrAccessLedger, err, rollbackOutboxTransaction(transaction))
		}
	}
	timeout := postgresTimeout(25 * time.Second)
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, timeout, "2000", timeout); err != nil {
		return nil, errors.Join(ErrAccessLedger, err, rollbackOutboxTransaction(transaction))
	}
	return transaction, nil
}

type accessLedgerProof struct {
	Recorded        bool   `json:"recorded"`
	Busy            bool   `json:"busy"`
	SnapshotID      string `json:"snapshot_id"`
	NetworkRevision int64  `json:"network_revision"`
	Digest          string `json:"digest"`
	StreamID        int64  `json:"stream_id"`
	Sequence        int64  `json:"sequence"`
	PreviousHash    string `json:"previous_hash"`
	Payload         string `json:"payload"`
}

func decodeAccessLedgerProof(encoded string, snapshot publicid.ID) (accessLedgerProof, error) {
	var proof accessLedgerProof
	if err := decodeStrictJSON(encoded, 65536, &proof); err != nil {
		return accessLedgerProof{}, ErrAccessLedger
	}
	if !proof.Recorded {
		if proof.SnapshotID != "" || proof.NetworkRevision != 0 || proof.Digest != "" || proof.StreamID != 0 ||
			proof.Sequence != 0 || proof.PreviousHash != "" || proof.Payload != "" {
			return accessLedgerProof{}, ErrAccessLedger
		}
		return proof, nil
	}
	digest, digestErr := hex.DecodeString(proof.Digest)
	previous, previousErr := hex.DecodeString(proof.PreviousHash)
	if proof.Busy || proof.SnapshotID != snapshot.String() || proof.NetworkRevision < 1 ||
		digestErr != nil || len(digest) != sha256.Size || previousErr != nil || len(previous) != sha256.Size ||
		proof.StreamID < 1 || proof.Sequence < 1 || len(proof.Payload) == 0 || len(proof.Payload) > 16384 ||
		!json.Valid([]byte(proof.Payload)) {
		return accessLedgerProof{}, ErrAccessLedger
	}
	return proof, nil
}

// hashAccessLedgerEvent binds the event to the stream head the database
// returned. The system actor and correlation are zero, as in other workers.
func hashAccessLedgerEvent(proof accessLedgerProof, change, event publicid.ID) ([sha256.Size]byte, error) {
	previous, err := hex.DecodeString(proof.PreviousHash)
	if err != nil || len(previous) != sha256.Size {
		return [sha256.Size]byte{}, ErrAccessLedger
	}
	digest, err := hex.DecodeString(proof.Digest)
	if err != nil || len(digest) != sha256.Size {
		return [sha256.Size]byte{}, ErrAccessLedger
	}
	aggregate, err := publicid.Parse(proof.SnapshotID)
	if err != nil {
		return [sha256.Size]byte{}, ErrAccessLedger
	}
	payloadHash := sha256.Sum256([]byte(proof.Payload))
	return audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: [sha256.Size]byte(previous), EventID: event, ChangeID: change,
		AggregateKind: accessLedgerAggregateKind, AggregateID: aggregate, AggregateVersion: 1,
		NetworkRevision: proof.NetworkRevision, Action: accessLedgerAction, Permission: accessLedgerPermission,
		AfterSemanticHash: [sha256.Size]byte(digest), AuditPayloadHash: payloadHash,
		OutboxEventClass: accessLedgerAction, OutboxPayloadHash: payloadHash,
	})
}

// decodeStrictJSON decodes exactly one bounded JSON value with no unknown fields.
func decodeStrictJSON(encoded string, maximum int, target any) error {
	if len(encoded) == 0 || len(encoded) > maximum {
		return ErrAccessLedger
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrAccessLedger
	}
	return nil
}

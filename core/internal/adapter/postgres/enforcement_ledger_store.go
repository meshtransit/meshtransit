package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/enforcementledger"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/policydigest"
)

var (
	// ErrInvalidEnforcementLedger reports unsafe construction or input.
	ErrInvalidEnforcementLedger = errors.New("invalid postgres enforcement ledger")
	// ErrEnforcementLedger classifies a failed discovery, record or retention call.
	ErrEnforcementLedger = errors.New("postgres enforcement ledger")
	// ErrEnforcementLedgerCommitUnknown forbids retry until state is re-read.
	ErrEnforcementLedgerCommitUnknown = errors.New("postgres enforcement ledger commit outcome unknown")
)

const (
	listEnforcementNetworksSQL = `SELECT mesh_ops.list_enforcement_networks_v1($1::UUID,$2::UUID,$3::INTEGER)::TEXT`
	listEnforcementDevicesSQL  = `SELECT mesh_ops.list_enforcement_devices_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::INTEGER)::TEXT`
	recordDeviceEnforcementSQL = `SELECT mesh_ops.record_device_enforcement_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BYTEA,$7::INTEGER,$8::BYTEA,$9::INTEGER,
    $10::TIMESTAMPTZ,$11::TIMESTAMPTZ,$12::UUID,$13::UUID)::TEXT`
	appendDeviceEnforcementEvidenceSQL = `SELECT mesh_ops.append_device_enforcement_evidence_v1(
    $1::UUID,$2::BIGINT,$3::BIGINT,$4::BYTEA,$5::BYTEA,$6::UUID,$7::UUID,$8::JSONB)`
	pruneDeviceEnforcementSQL       = `SELECT mesh_ops.prune_device_enforcement_v1($1::UUID,$2::INTEGER)`
	pruneDeviceCaptiveWindowsSQL    = `SELECT mesh_ops.prune_device_captive_windows_v1($1::UUID,$2::INTEGER)`
	pruneGatewayKeyEventsSQL        = `SELECT mesh_ops.prune_kubernetes_gateway_key_events_v1($1::UUID,$2::INTEGER)`
	enforcementLedgerPermission     = "system.reconcile"
	enforcementLedgerAggregateKind  = "device_enforcement_event"
	enforcementLedgerMaximumPage    = 500
	enforcementLedgerMaximumPrune   = 10000
	enforcementLedgerMaximumPayload = 8192
)

// EnforcementLedgerStore records enforcement evidence through a worker pool
// only. It holds no authority cache, sticky transaction or goroutine.
type EnforcementLedgerStore struct{ database outboxDatabase }

var (
	_ enforcementledger.Directory = (*EnforcementLedgerStore)(nil)
	_ enforcementledger.Recorder  = (*EnforcementLedgerStore)(nil)
	_ enforcementledger.Pruner    = (*EnforcementLedgerStore)(nil)
)

// NewEnforcementLedgerStore rejects non-worker pools before any effect.
func NewEnforcementLedgerStore(pool *Pool) (*EnforcementLedgerStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, ErrInvalidEnforcementLedger
	}
	return &EnforcementLedgerStore{database: pool.outboxDatabase}, nil
}

// ListNetworks reads one page of the installation's Networks.
func (store *EnforcementLedgerStore) ListNetworks(ctx context.Context, installation deployment.ID, after network.ID,
	limit int) ([]network.Scope, error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() ||
		limit < 1 || limit > enforcementLedgerMaximumPage || (after != network.ID{} && !after.IsValid()) {
		return nil, ErrInvalidEnforcementLedger
	}
	var cursor any
	if after.IsValid() {
		cursor = after.String()
	}
	encoded, err := store.readOnly(ctx, listEnforcementNetworksSQL, installation.String(), cursor, limit)
	if err != nil {
		return nil, err
	}
	var record struct {
		Items []struct {
			WorkspaceID string `json:"workspace_id"`
			NetworkID   string `json:"network_id"`
		} `json:"items"`
	}
	if err := decodeStrictJSON(encoded, 1<<20, &record); err != nil || record.Items == nil ||
		len(record.Items) > limit {
		return nil, ErrEnforcementLedger
	}
	scopes := make([]network.Scope, 0, len(record.Items))
	for _, item := range record.Items {
		workspaceID, workspaceErr := workspace.ParseID(item.WorkspaceID)
		networkID, networkErr := network.ParseID(item.NetworkID)
		scope, scopeErr := network.NewScope(workspaceID, networkID)
		if workspaceErr != nil || networkErr != nil || scopeErr != nil {
			return nil, ErrEnforcementLedger
		}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

// ListDevices reads one page of a Network's Devices with open intervals.
func (store *EnforcementLedgerStore) ListDevices(ctx context.Context, installation deployment.ID,
	scope network.Scope, after node.ID, limit int) ([]enforcementledger.Target, error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || !scope.IsValid() ||
		limit < 1 || limit > enforcementLedgerMaximumPage || (after != node.ID{} && !after.IsValid()) {
		return nil, ErrInvalidEnforcementLedger
	}
	var cursor any
	if after.IsValid() {
		cursor = after.String()
	}
	encoded, err := store.readOnly(ctx, listEnforcementDevicesSQL, installation.String(),
		scope.WorkspaceID().String(), scope.NetworkID().String(), cursor, limit)
	if err != nil {
		return nil, err
	}
	return decodeEnforcementTargets(encoded, limit)
}

func decodeEnforcementTargets(encoded string, limit int) ([]enforcementledger.Target, error) {
	var record struct {
		Items []struct {
			DeviceID        string  `json:"device_id"`
			State           *string `json:"state"`
			DeliveredDigest *string `json:"delivered_digest"`
			EnforcedDigest  *string `json:"enforced_digest"`
		} `json:"items"`
	}
	if err := decodeStrictJSON(encoded, 1<<20, &record); err != nil || record.Items == nil ||
		len(record.Items) > limit {
		return nil, ErrEnforcementLedger
	}
	targets := make([]enforcementledger.Target, 0, len(record.Items))
	for _, item := range record.Items {
		deviceID, err := node.ParseID(item.DeviceID)
		if err != nil {
			return nil, ErrEnforcementLedger
		}
		target := enforcementledger.Target{DeviceID: deviceID}
		switch {
		case item.State == nil && item.DeliveredDigest == nil && item.EnforcedDigest == nil:
		case item.State != nil && item.DeliveredDigest != nil && item.EnforcedDigest != nil:
			delivered, deliveredErr := hexDigest(*item.DeliveredDigest)
			enforced, enforcedErr := hexDigest(*item.EnforcedDigest)
			state := enforcementledger.State(*item.State)
			if deliveredErr != nil || enforcedErr != nil ||
				(state != enforcementledger.StateEnforced && state != enforcementledger.StateMismatch) {
				return nil, ErrEnforcementLedger
			}
			target.Open = enforcementledger.Interval{State: state, Delivered: delivered, Enforced: enforced}
		default:
			return nil, ErrEnforcementLedger
		}
		targets = append(targets, target)
	}
	return targets, nil
}

func hexDigest(text string) (policydigest.Digest, error) {
	decoded, err := hex.DecodeString(text)
	if err != nil || len(decoded) != sha256.Size {
		return policydigest.Digest{}, ErrEnforcementLedger
	}
	return policydigest.Digest(decoded), nil
}

// Record writes one observation and, for a change into or out of mismatch,
// seals its audit event in the same transaction. An unknown commit outcome
// is reported and never retried here; the next pass re-reads committed state.
func (store *EnforcementLedgerStore) Record(ctx context.Context, installation deployment.ID,
	observation enforcementledger.Observation) (enforcementledger.Outcome, error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() ||
		!observation.Scope.IsValid() || !observation.DeviceID.IsValid() || observation.NetworkRevision < 1 ||
		observation.Delivered.IsZero() || observation.Enforced.IsZero() ||
		observation.AppliedAt.IsZero() || observation.ReportedAt.IsZero() {
		return enforcementledger.OutcomeUnchanged, ErrInvalidEnforcementLedger
	}
	return retryReadConflict(ctx, func() (enforcementledger.Outcome, error) {
		return store.recordOnce(ctx, installation, observation)
	})
}

func (store *EnforcementLedgerStore) recordOnce(ctx context.Context, installation deployment.ID,
	observation enforcementledger.Observation) (outcome enforcementledger.Outcome, resultErr error) {
	var ids [4]publicid.ID
	for index := range ids {
		id, err := freshPublicID()
		if err != nil {
			return enforcementledger.OutcomeUnchanged, errors.Join(ErrEnforcementLedger, err)
		}
		ids[index] = id
	}
	eventID, change, auditEventID, outboxID := ids[0], ids[1], ids[2], ids[3]
	transaction, err := store.begin(ctx, false)
	if err != nil {
		return enforcementledger.OutcomeUnchanged, err
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
			outcome = enforcementledger.OutcomeUnchanged
		}
	}()
	delivered, enforced := observation.Delivered.Digest, observation.Enforced.Digest
	var encoded string
	if err := transaction.QueryRow(ctx, recordDeviceEnforcementSQL, installation.String(),
		observation.Scope.WorkspaceID().String(), observation.Scope.NetworkID().String(),
		observation.DeviceID.String(), observation.NetworkRevision, delivered[:], observation.Delivered.Grants,
		enforced[:], observation.Enforced.Grants, observation.AppliedAt.UTC(), observation.ReportedAt.UTC(),
		eventID.String(), change.String()).Scan(&encoded); err != nil {
		return enforcementledger.OutcomeUnchanged, errors.Join(ErrEnforcementLedger, err)
	}
	proof, err := decodeEnforcementProof(encoded, eventID)
	if err != nil {
		return enforcementledger.OutcomeUnchanged, err
	}
	switch {
	case proof.Busy:
		outcome = enforcementledger.OutcomeBusy
	case proof.Audited:
		hash, err := hashEnforcementEvent(proof, change, auditEventID)
		if err != nil {
			return enforcementledger.OutcomeUnchanged, errors.Join(ErrEnforcementLedger, err)
		}
		previous, _ := hex.DecodeString(proof.PreviousHash)
		var sequence int64
		if err := transaction.QueryRow(ctx, appendDeviceEnforcementEvidenceSQL, eventID.String(), proof.StreamID,
			proof.Sequence, previous, hash[:], auditEventID.String(), outboxID.String(), proof.Payload,
		).Scan(&sequence); err != nil {
			return enforcementledger.OutcomeUnchanged, errors.Join(ErrEnforcementLedger, err)
		}
		if sequence != proof.Sequence {
			return enforcementledger.OutcomeUnchanged, ErrEnforcementLedger
		}
		outcome = enforcementledger.OutcomeAudited
	case proof.Recorded:
		outcome = enforcementledger.OutcomeRecorded
	default:
		outcome = enforcementledger.OutcomeUnchanged
	}
	if err := ctx.Err(); err != nil {
		return enforcementledger.OutcomeUnchanged, errors.Join(ErrEnforcementLedger, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return enforcementledger.OutcomeUnchanged,
			errors.Join(ErrEnforcementLedger, ErrEnforcementLedgerCommitUnknown, err)
	}
	committed = true
	return outcome, nil
}

// Prune removes one bounded batch of rows past retention.
func (store *EnforcementLedgerStore) Prune(ctx context.Context, installation deployment.ID,
	limit int) (removed int, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() ||
		limit < 1 || limit > enforcementLedgerMaximumPrune {
		return 0, ErrInvalidEnforcementLedger
	}
	transaction, err := store.begin(ctx, false)
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
	if err := transaction.QueryRow(ctx, pruneDeviceEnforcementSQL, installation.String(), limit).Scan(&removed); err != nil {
		return 0, errors.Join(ErrEnforcementLedger, err)
	}
	// The captive portal windows Devices reported (schema 212) go with the
	// enforcement evidence, in what the call has left.
	if removed >= 0 && removed < limit {
		var captive int
		if err := transaction.QueryRow(ctx, pruneDeviceCaptiveWindowsSQL, installation.String(),
			limit-removed).Scan(&captive); err != nil {
			return 0, errors.Join(ErrEnforcementLedger, err)
		}
		if captive < 0 {
			return 0, ErrEnforcementLedger
		}
		removed += captive
	}
	// So do Kubernetes gateways' key events (schema 229).
	if removed >= 0 && removed < limit {
		var keyEvents int
		if err := transaction.QueryRow(ctx, pruneGatewayKeyEventsSQL, installation.String(),
			limit-removed).Scan(&keyEvents); err != nil {
			return 0, errors.Join(ErrEnforcementLedger, err)
		}
		if keyEvents < 0 {
			return 0, ErrEnforcementLedger
		}
		removed += keyEvents
	}
	if removed < 0 {
		return 0, ErrEnforcementLedger
	}
	if err := transaction.Commit(ctx); err != nil {
		return 0, errors.Join(ErrEnforcementLedger, ErrEnforcementLedgerCommitUnknown, err)
	}
	committed = true
	return removed, nil
}

func (store *EnforcementLedgerStore) readOnly(ctx context.Context, query string, arguments ...any) (result string,
	resultErr error) {
	transaction, err := store.begin(ctx, true)
	if err != nil {
		return "", err
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
			result = ""
		}
	}()
	var encoded string
	if err := transaction.QueryRow(ctx, query, arguments...).Scan(&encoded); err != nil {
		return "", errors.Join(ErrEnforcementLedger, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return "", errors.Join(ErrEnforcementLedger, err)
	}
	committed = true
	return encoded, nil
}

func (store *EnforcementLedgerStore) begin(ctx context.Context, readOnly bool) (outboxTransaction, error) {
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(ErrEnforcementLedger, err)
	}
	transaction, err := store.database.Begin(ctx, readOnly)
	if err != nil {
		return nil, errors.Join(ErrEnforcementLedger, err)
	}
	if transaction == nil {
		return nil, ErrEnforcementLedger
	}
	timeout := postgresTimeout(10 * time.Second)
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, timeout, "2000", timeout); err != nil {
		return nil, errors.Join(ErrEnforcementLedger, err, rollbackOutboxTransaction(transaction))
	}
	return transaction, nil
}

type enforcementProof struct {
	Recorded        bool   `json:"recorded"`
	Busy            bool   `json:"busy"`
	Audited         bool   `json:"audited"`
	EventID         string `json:"event_id"`
	Action          string `json:"action"`
	NetworkRevision int64  `json:"network_revision"`
	Digest          string `json:"digest"`
	StreamID        int64  `json:"stream_id"`
	Sequence        int64  `json:"sequence"`
	PreviousHash    string `json:"previous_hash"`
	Payload         string `json:"payload"`
}

func decodeEnforcementProof(encoded string, event publicid.ID) (enforcementProof, error) {
	var proof enforcementProof
	if err := decodeStrictJSON(encoded, 65536, &proof); err != nil {
		return enforcementProof{}, ErrEnforcementLedger
	}
	if !proof.Audited {
		if (proof.Busy && proof.Recorded) || proof.EventID != "" || proof.Action != "" || proof.NetworkRevision != 0 ||
			proof.Digest != "" || proof.StreamID != 0 || proof.Sequence != 0 || proof.PreviousHash != "" ||
			proof.Payload != "" {
			return enforcementProof{}, ErrEnforcementLedger
		}
		return proof, nil
	}
	digest, digestErr := hex.DecodeString(proof.Digest)
	previous, previousErr := hex.DecodeString(proof.PreviousHash)
	if proof.Busy || !proof.Recorded || proof.EventID != event.String() || proof.NetworkRevision < 1 ||
		(proof.Action != "device.enforcement_mismatch" && proof.Action != "device.enforcement_restored") ||
		digestErr != nil || len(digest) != sha256.Size || previousErr != nil || len(previous) != sha256.Size ||
		proof.StreamID < 1 || proof.Sequence < 1 || len(proof.Payload) == 0 ||
		len(proof.Payload) > enforcementLedgerMaximumPayload || !json.Valid([]byte(proof.Payload)) {
		return enforcementProof{}, ErrEnforcementLedger
	}
	return proof, nil
}

// hashEnforcementEvent binds the event to the stream head the database
// returned. The system actor and correlation are zero, as in other workers.
func hashEnforcementEvent(proof enforcementProof, change, event publicid.ID) ([sha256.Size]byte, error) {
	previous, err := hex.DecodeString(proof.PreviousHash)
	if err != nil || len(previous) != sha256.Size {
		return [sha256.Size]byte{}, ErrEnforcementLedger
	}
	digest, err := hex.DecodeString(proof.Digest)
	if err != nil || len(digest) != sha256.Size {
		return [sha256.Size]byte{}, ErrEnforcementLedger
	}
	aggregate, err := publicid.Parse(proof.EventID)
	if err != nil {
		return [sha256.Size]byte{}, ErrEnforcementLedger
	}
	payloadHash := sha256.Sum256([]byte(proof.Payload))
	return audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: [sha256.Size]byte(previous), EventID: event, ChangeID: change,
		AggregateKind: enforcementLedgerAggregateKind, AggregateID: aggregate, AggregateVersion: 1,
		NetworkRevision: proof.NetworkRevision, Action: proof.Action, Permission: enforcementLedgerPermission,
		AfterSemanticHash: [sha256.Size]byte(digest), AuditPayloadHash: payloadHash,
		OutboxEventClass: proof.Action, OutboxPayloadHash: payloadHash,
	})
}

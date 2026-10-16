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
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/sharing/devicealias"
	"meshtransit.net/core/internal/domain/workspace"
)

var (
	// ErrInvalidDeviceAliasWorker reports unsafe worker construction or input.
	ErrInvalidDeviceAliasWorker = errors.New("invalid postgres Device alias worker")
	// ErrDeviceAliasChange classifies a failed guarded alias change.
	ErrDeviceAliasChange = errors.New("change postgres Device aliases")
	// ErrDeviceAliasCommitUnknown forbids retry until durable state is resolved.
	ErrDeviceAliasCommitUnknown = errors.New("postgres Device alias commit outcome unknown")
)

// DeviceAliasWorkerStore exposes guarded functions through a worker pool only.
// It holds no authority cache, sticky transaction, credentials or goroutines.
type DeviceAliasWorkerStore struct{ database outboxDatabase }

var _ devicealias.Changes = (*DeviceAliasWorkerStore)(nil)

// NewDeviceAliasWorkerStore rejects non-worker pools before any effect.
func NewDeviceAliasWorkerStore(pool *Pool) (*DeviceAliasWorkerStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, ErrInvalidDeviceAliasWorker
	}
	return &DeviceAliasWorkerStore{database: pool.outboxDatabase}, nil
}

const prepareDeviceAliasChangeSQL = `SELECT mesh_ops.prepare_device_alias_change_v2(
 $1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::BIGINT,$7::UUID[],$8::UUID,$9::UUID,$10::TEXT)`

// prepareScaledDeviceAliasChangeSQL is v2 with a 10000 consumer budget per
// endpoint and the readiness check through the map reader bounded by the map
// peer limit (schema 147); used once the operator granted it to the worker.
const prepareScaledDeviceAliasChangeSQL = `SELECT mesh_ops.prepare_device_alias_change_v3(
 $1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::BIGINT,$7::UUID[],$8::UUID,$9::UUID,$10::TEXT)`

// prepareReadmittingDeviceAliasChangeSQL is v3 that reserves fresh source
// aliases and readiness for a consumer Device whose share was withdrawn and
// that is authorized again (schema 170); used with load work v3.
const prepareReadmittingDeviceAliasChangeSQL = `SELECT mesh_ops.prepare_device_alias_change_v4(
 $1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::BIGINT,$7::UUID[],$8::UUID,$9::UUID,$10::TEXT)`

// prepareProviderReadmittingDeviceAliasChangeSQL is v4 that also gives a
// resumed provider Device the endpoint's own Resource aliases back (schema
// 171); used with load work v4.
const prepareProviderReadmittingDeviceAliasChangeSQL = `SELECT mesh_ops.prepare_device_alias_change_v5(
 $1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::BIGINT,$7::UUID[],$8::UUID,$9::UUID,$10::TEXT)`

// deviceAliasWorkerVersionSQL reports the newest prepare the operator granted
// to the worker: 5 when prepare v5 and load work v4 (schema 171) both are, 4
// when prepare v4 and load work v3 (schema 170) both are, which the worker
// then uses together, else 3 (schema 147) or 2.
const deviceAliasWorkerVersionSQL = `SELECT CASE
 WHEN COALESCE(pg_catalog.has_function_privilege(
  pg_catalog.to_regprocedure('mesh_ops.prepare_device_alias_change_v5(uuid,uuid,uuid,bigint,bigint,bigint,uuid[],uuid,uuid,text)'), 'EXECUTE'), FALSE)
  AND COALESCE(pg_catalog.has_function_privilege(
  pg_catalog.to_regprocedure('mesh_ops.load_device_alias_work_v4(uuid,uuid,uuid,integer)'), 'EXECUTE'), FALSE) THEN 5
 WHEN COALESCE(pg_catalog.has_function_privilege(
  pg_catalog.to_regprocedure('mesh_ops.prepare_device_alias_change_v4(uuid,uuid,uuid,bigint,bigint,bigint,uuid[],uuid,uuid,text)'), 'EXECUTE'), FALSE)
  AND COALESCE(pg_catalog.has_function_privilege(
  pg_catalog.to_regprocedure('mesh_ops.load_device_alias_work_v3(uuid,uuid,uuid,integer)'), 'EXECUTE'), FALSE) THEN 4
 WHEN COALESCE(pg_catalog.has_function_privilege(
  pg_catalog.to_regprocedure('mesh_ops.prepare_device_alias_change_v3(uuid,uuid,uuid,bigint,bigint,bigint,uuid[],uuid,uuid,text)'), 'EXECUTE'), FALSE) THEN 3
 ELSE 2 END`
const prepareDeviceAliasResourceQuarantineSQL = `SELECT mesh_ops.prepare_device_alias_resource_quarantine_v2($1::UUID,$2::UUID,$3::BIGINT,$4::UUID)`

const prepareDeviceAliasWithdrawalSQL = `SELECT mesh_ops.prepare_device_alias_withdrawal_v2($1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::UUID,$6::TEXT)`
const finalizeDeviceAliasWithdrawalSQL = `SELECT mesh_ops.finalize_device_alias_withdrawal_v2($1::UUID,$2::UUID,$3::BIGINT,$4::UUID,$5::TEXT,$6::JSONB)`

const finalizeDeviceAliasChangeSQL = `SELECT mesh_ops.finalize_device_alias_change_v1($1::UUID,$2::UUID,$3::BIGINT,$4::UUID,$5::TEXT,$6::JSONB)`

// Change prepares state and locks authority before audit heads, hashes evidence
// locally, then finalizes and commits in the same bounded transaction. There is
// no external network effect while locks are held and no retry on unknown commit.
func (store *DeviceAliasWorkerStore) Change(ctx context.Context, intent devicealias.ChangeIntent) (changed bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !intent.IsValid() {
		return false, ErrInvalidDeviceAliasWorker
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrDeviceAliasChange, err)
	}
	var ids [10]publicid.ID
	for index := range ids {
		id, err := freshPublicID()
		if err != nil {
			return false, errors.Join(ErrDeviceAliasChange, err)
		}
		ids[index] = id
	}
	transaction, beginErr := store.database.Begin(ctx, false)
	committed := false
	if transaction != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
			}
			if resultErr != nil {
				changed = false
			}
		}()
	}
	if beginErr != nil {
		return false, errors.Join(ErrDeviceAliasChange, beginErr)
	}
	if transaction == nil {
		return false, ErrDeviceAliasChange
	}
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, "5000", "1000", "10000"); err != nil {
		return false, errors.Join(ErrDeviceAliasChange, err)
	}
	leases := []string{ids[0].String(), ids[1].String(), ids[2].String(), ids[3].String()}
	var encoded []byte
	prepareQuery := prepareDeviceAliasChangeSQL
	var version int
	if err := transaction.QueryRow(ctx, deviceAliasWorkerVersionSQL).Scan(&version); err != nil {
		return false, errors.Join(ErrDeviceAliasChange, err)
	}
	switch version {
	case 5:
		prepareQuery = prepareProviderReadmittingDeviceAliasChangeSQL
	case 4:
		prepareQuery = prepareReadmittingDeviceAliasChangeSQL
	case 3:
		prepareQuery = prepareScaledDeviceAliasChangeSQL
	}
	prepareArgs := []any{intent.DeploymentID.String(), intent.EndpointID.String(), intent.ConsumerID.String(), intent.EndpointGeneration, intent.ProviderNodeEpoch, intent.ConsumerNodeEpoch, leases, ids[4].String(), ids[5].String(), string(intent.Mode)}
	if intent.Mode.Withdraws() {
		prepareQuery = prepareDeviceAliasWithdrawalSQL
		prepareArgs = []any{intent.DeploymentID.String(), intent.EndpointID.String(), intent.ConsumerID.String(), intent.EndpointGeneration, ids[5].String(), string(intent.Mode)}
	}
	if intent.Mode == devicealias.QuarantineResource {
		prepareQuery = prepareDeviceAliasResourceQuarantineSQL
		prepareArgs = []any{intent.DeploymentID.String(), intent.EndpointID.String(), intent.EndpointGeneration, ids[5].String()}
	}
	if err := transaction.QueryRow(ctx, prepareQuery, prepareArgs...).Scan(&encoded); err != nil {
		return false, errors.Join(ErrDeviceAliasChange, err)
	}
	proof, err := decodeDeviceAliasChangeProof(encoded, intent, ids[5])
	if err != nil {
		return false, errors.Join(ErrDeviceAliasChange, err)
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrDeviceAliasChange, err)
	}
	if proof.Changed {
		events, err := hashDeviceAliasEvents(proof, ids)
		if err != nil {
			return false, errors.Join(ErrDeviceAliasChange, err)
		}
		var count int
		finalizeQuery, selector := finalizeDeviceAliasChangeSQL, proof.AggregateKind
		if intent.Mode.Withdraws() {
			finalizeQuery, selector = finalizeDeviceAliasWithdrawalSQL, string(intent.Mode)
		}
		if err := transaction.QueryRow(ctx, finalizeQuery, intent.DeploymentID.String(), intent.EndpointID.String(), intent.EndpointGeneration,
			ids[5].String(), selector, events).Scan(&count); err != nil || count != 2 {
			return false, errors.Join(ErrDeviceAliasChange, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrDeviceAliasChange, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return false, errors.Join(ErrDeviceAliasChange, ErrDeviceAliasCommitUnknown, err)
	}
	committed = true
	return proof.Changed, nil
}

type deviceAliasChangeProof struct {
	Changed          bool                  `json:"changed"`
	TransactionID    string                `json:"transaction_id"`
	ChangeID         string                `json:"change_id"`
	EndpointID       string                `json:"endpoint_id"`
	AggregateKind    string                `json:"aggregate_kind"`
	AggregateID      string                `json:"aggregate_id"`
	AggregateVersion int64                 `json:"aggregate_version"`
	Action           string                `json:"action,omitempty"`
	Deadline         time.Time             `json:"deadline"`
	Events           []deviceAliasEvidence `json:"events"`
}

type deviceAliasEvidence struct {
	WorkspaceID     string `json:"workspace_id"`
	NetworkID       string `json:"network_id"`
	StreamID        int64  `json:"stream_id"`
	Sequence        int64  `json:"sequence"`
	PreviousHash    string `json:"previous_hash"`
	NetworkRevision int64  `json:"network_revision"`
	SharingRevision int64  `json:"sharing_revision"`
	AuditPayload    string `json:"audit_payload"`
	OutboxPayload   string `json:"outbox_payload"`
	EventID         string `json:"event_id,omitempty"`
	OutboxID        string `json:"outbox_id,omitempty"`
	EventHash       string `json:"event_hash,omitempty"`
}

func decodeDeviceAliasChangeProof(encoded []byte, intent devicealias.ChangeIntent, change publicid.ID) (deviceAliasChangeProof, error) {
	if len(encoded) == 0 || len(encoded) > 65536 {
		return deviceAliasChangeProof{}, ErrDeviceAliasChange
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &shape); err != nil || shape == nil ||
		(string(shape["changed"]) != "true" && string(shape["changed"]) != "false") || len(shape["events"]) == 0 || bytes.Equal(shape["events"], []byte("null")) {
		return deviceAliasChangeProof{}, ErrDeviceAliasChange
	}
	var proof deviceAliasChangeProof
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return deviceAliasChangeProof{}, ErrDeviceAliasChange
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return deviceAliasChangeProof{}, ErrDeviceAliasChange
	}
	if !proof.Changed {
		if len(proof.Events) != 0 || proof.TransactionID != "" || proof.ChangeID != "" || proof.EndpointID != "" || proof.AggregateKind != "" || proof.AggregateID != "" || proof.AggregateVersion != 0 || proof.Action != "" || !proof.Deadline.IsZero() {
			return deviceAliasChangeProof{}, ErrDeviceAliasChange
		}
		return proof, nil
	}
	transaction, err := strconv.ParseInt(proof.TransactionID, 10, 64)
	if err != nil || transaction <= 0 || proof.ChangeID != change.String() || proof.EndpointID != intent.EndpointID.String() || len(proof.Events) != 2 || proof.AggregateVersion <= 0 || !proof.Deadline.After(time.Now()) {
		return deviceAliasChangeProof{}, ErrDeviceAliasChange
	}
	wantKind := "device_alias_lease"
	if intent.Mode == devicealias.Ready || intent.Mode == devicealias.Withdraw {
		wantKind = "device_alias_client_readiness"
	}
	if intent.Mode.Withdraws() && proof.Action != "sharing.device_alias."+string(intent.Mode) || !intent.Mode.Withdraws() && proof.Action != "" {
		return deviceAliasChangeProof{}, ErrDeviceAliasChange
	}
	if proof.AggregateKind != wantKind {
		return deviceAliasChangeProof{}, ErrDeviceAliasChange
	}
	if _, err := publicid.Parse(proof.AggregateID); err != nil {
		return deviceAliasChangeProof{}, ErrDeviceAliasChange
	}
	for index, event := range proof.Events {
		workspaceID, workspaceErr := workspace.ParseID(event.WorkspaceID)
		networkID, networkErr := network.ParseID(event.NetworkID)
		if _, err := network.NewScope(workspaceID, networkID); err != nil || workspaceErr != nil || networkErr != nil ||
			event.StreamID <= 0 || event.Sequence <= 0 || event.NetworkRevision <= 0 || event.SharingRevision <= 0 ||
			len(event.PreviousHash) != 64 || len(event.AuditPayload) == 0 || len(event.AuditPayload) > 16384 || len(event.OutboxPayload) == 0 || len(event.OutboxPayload) > 16384 ||
			event.EventID != "" || event.OutboxID != "" || event.EventHash != "" || !json.Valid([]byte(event.AuditPayload)) || !json.Valid([]byte(event.OutboxPayload)) {
			return deviceAliasChangeProof{}, ErrDeviceAliasChange
		}
		if previous, err := hex.DecodeString(event.PreviousHash); err != nil || len(previous) != sha256.Size {
			return deviceAliasChangeProof{}, ErrDeviceAliasChange
		}
		if index == 1 && (event.NetworkID == proof.Events[0].NetworkID || event.StreamID == proof.Events[0].StreamID) {
			return deviceAliasChangeProof{}, ErrDeviceAliasChange
		}
	}
	return proof, nil
}

func hashDeviceAliasEvents(proof deviceAliasChangeProof, ids [10]publicid.ID) ([]byte, error) {
	aggregateID, err := publicid.Parse(proof.AggregateID)
	if err != nil {
		return nil, ErrDeviceAliasChange
	}
	action := "sharing.device_alias.reserve"
	if proof.AggregateKind == "device_alias_client_readiness" {
		action = "sharing.device_alias.ready"
	}
	if proof.Action != "" {
		action = proof.Action
	}
	for index := range proof.Events {
		event := &proof.Events[index]
		previous, err := hex.DecodeString(event.PreviousHash)
		if err != nil || len(previous) != sha256.Size {
			return nil, ErrDeviceAliasChange
		}
		eventID, outboxID := ids[6+index*2], ids[7+index*2]
		hash, err := audit.HashEvent(audit.EventHashMaterial{
			PreviousHash: [32]byte(previous), EventID: eventID, ChangeID: ids[5], AggregateKind: proof.AggregateKind, AggregateID: aggregateID, AggregateVersion: proof.AggregateVersion,
			NetworkRevision: event.NetworkRevision, Action: action, Permission: "sharing.client_alias", AuditPayloadHash: sha256.Sum256([]byte(event.AuditPayload)),
			OutboxEventClass: "network.revision.advanced", OutboxPayloadHash: sha256.Sum256([]byte(event.OutboxPayload)),
		})
		if err != nil {
			return nil, err
		}
		event.EventID, event.OutboxID, event.EventHash = eventID.String(), outboxID.String(), hex.EncodeToString(hash[:])
	}
	return json.Marshal(proof.Events)
}

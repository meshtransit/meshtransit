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
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/domain/sharing/contractexpiry"
	"meshtransit.net/core/internal/domain/workspace"
)

var (
	// ErrInvalidTrustContractExpiry reports unsafe construction or input.
	ErrInvalidTrustContractExpiry = errors.New("invalid postgres Trust Contract expiry")
	// ErrTrustContractExpiry classifies a failed discovery or finalization.
	ErrTrustContractExpiry = errors.New("finalize postgres Trust Contract expiry")
	// ErrTrustContractExpiryCommitUnknown forbids retry until state is re-read.
	ErrTrustContractExpiryCommitUnknown = errors.New("postgres Trust Contract expiry commit outcome unknown")
)

const (
	listExpiredTrustContractsSQL     = `SELECT mesh_ops.list_expired_trust_contracts_v1($1::UUID,$2::TIMESTAMPTZ,$3::UUID,$4::INTEGER)`
	prepareTrustContractExpirySQL    = `SELECT mesh_ops.prepare_trust_contract_expiry_v1($1::UUID,$2::UUID,$3::UUID)`
	finalizeTrustContractExpirySQL   = `SELECT mesh_ops.finalize_trust_contract_expiry_v1($1::UUID,$2::UUID,$3::UUID,$4::JSONB)`
	listDeviceRemovalsSQL            = `SELECT mesh_ops.list_trust_contract_device_removals_v1($1::UUID,$2::TIMESTAMPTZ,$3::UUID,$4::INTEGER)`
	prepareDeviceRemovalSQL          = `SELECT mesh_ops.prepare_trust_contract_device_removal_v1($1::UUID,$2::UUID,$3::UUID)`
	finalizeDeviceRemovalSQL         = `SELECT mesh_ops.finalize_trust_contract_device_removal_v1($1::UUID,$2::UUID,$3::UUID,$4::JSONB)`
	trustContractExpiryAction        = "trust_contract.expired"
	trustContractInvalidatedAction   = "trust_contract.invalidated"
	trustContractExpiryPermission    = "system.reconcile"
	trustContractExpiryAggregateKind = "trust_contract"
)

// trustContractEnding names the entry points of one reason to end contracts,
// the audit action they record and the instant their discovery orders by.
type trustContractEnding struct {
	listSQL, prepareSQL, finalizeSQL, action, instant string
}

var (
	trustContractExpiry = trustContractEnding{
		listSQL: listExpiredTrustContractsSQL, prepareSQL: prepareTrustContractExpirySQL,
		finalizeSQL: finalizeTrustContractExpirySQL, action: trustContractExpiryAction, instant: "expires_at",
	}
	trustContractDeviceRemoval = trustContractEnding{
		listSQL: listDeviceRemovalsSQL, prepareSQL: prepareDeviceRemovalSQL,
		finalizeSQL: finalizeDeviceRemovalSQL, action: trustContractInvalidatedAction, instant: "requested_at",
	}
)

// trustContractEndStore runs one finalizer through a worker pool only. It
// holds no authority cache, sticky transaction or goroutine.
type trustContractEndStore struct {
	database outboxDatabase
	ending   trustContractEnding
}

// TrustContractExpiryStore ends contracts past their expiry.
type TrustContractExpiryStore struct{ trustContractEndStore }

// TrustContractDeviceRemovalStore ends contracts whose provider Device was
// removed, as queued by the database when the Device left.
type TrustContractDeviceRemovalStore struct{ trustContractEndStore }

var (
	_ contractexpiry.Candidates = (*TrustContractExpiryStore)(nil)
	_ contractexpiry.Finalizer  = (*TrustContractExpiryStore)(nil)
	_ contractexpiry.Candidates = (*TrustContractDeviceRemovalStore)(nil)
	_ contractexpiry.Finalizer  = (*TrustContractDeviceRemovalStore)(nil)
)

func workerEndStore(pool *Pool, ending trustContractEnding) (trustContractEndStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return trustContractEndStore{}, ErrInvalidTrustContractExpiry
	}
	return trustContractEndStore{database: pool.outboxDatabase, ending: ending}, nil
}

// NewTrustContractExpiryStore rejects non-worker pools before any effect.
func NewTrustContractExpiryStore(pool *Pool) (*TrustContractExpiryStore, error) {
	store, err := workerEndStore(pool, trustContractExpiry)
	if err != nil {
		return nil, err
	}
	return &TrustContractExpiryStore{store}, nil
}

// NewTrustContractDeviceRemovalStore rejects non-worker pools before any effect.
func NewTrustContractDeviceRemovalStore(pool *Pool) (*TrustContractDeviceRemovalStore, error) {
	store, err := workerEndStore(pool, trustContractDeviceRemoval)
	if err != nil {
		return nil, err
	}
	return &TrustContractDeviceRemovalStore{store}, nil
}

// List reads one keyset page of open contracts to end in one read-only
// transaction. Discovery writes no mutation, audit or outbox row.
func (store *trustContractEndStore) List(ctx context.Context, installation deployment.ID, after contractexpiry.Cursor, limit int) (result contractexpiry.Page, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || !after.IsValid() || limit < 1 || limit > 128 {
		return contractexpiry.Page{}, ErrInvalidTrustContractExpiry
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return contractexpiry.Page{}, errors.Join(ErrTrustContractExpiry, err)
	}
	transaction, beginErr := store.database.Begin(ctx, true)
	committed := false
	if transaction != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
			}
			if resultErr != nil {
				result = contractexpiry.Page{}
			}
		}()
	}
	if beginErr != nil {
		return contractexpiry.Page{}, errors.Join(ErrTrustContractExpiry, beginErr)
	}
	if transaction == nil {
		return contractexpiry.Page{}, ErrTrustContractExpiry
	}
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, "3000", "1000", "5000"); err != nil {
		return contractexpiry.Page{}, errors.Join(ErrTrustContractExpiry, err)
	}
	var afterInstant, afterContract any
	if !after.IsZero() {
		afterInstant, afterContract = after.At, after.ContractID.String()
	}
	var encoded []byte
	if err := transaction.QueryRow(ctx, store.ending.listSQL, installation.String(), afterInstant, afterContract, limit).Scan(&encoded); err != nil {
		return contractexpiry.Page{}, errors.Join(ErrTrustContractExpiry, err)
	}
	page, err := decodeTrustContractPage(encoded, store.ending.instant, after, limit)
	if err != nil {
		return contractexpiry.Page{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return contractexpiry.Page{}, errors.Join(ErrTrustContractExpiry, err)
	}
	committed = true
	return page, nil
}

// decodeTrustContractPage reads items of exactly contract_id and the named
// instant; any other key is rejected.
func decodeTrustContractPage(encoded []byte, instant string, after contractexpiry.Cursor, limit int) (contractexpiry.Page, error) {
	if len(encoded) == 0 || len(encoded) > 65536 {
		return contractexpiry.Page{}, ErrTrustContractExpiry
	}
	var record struct {
		Items []map[string]json.RawMessage `json:"items"`
		Done  *bool                        `json:"done"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Items == nil || record.Done == nil || len(record.Items) > limit {
		return contractexpiry.Page{}, ErrTrustContractExpiry
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return contractexpiry.Page{}, ErrTrustContractExpiry
	}
	page := contractexpiry.Page{Done: *record.Done, Items: make([]contractexpiry.Candidate, 0, len(record.Items))}
	for _, item := range record.Items {
		var contractText string
		var at time.Time
		if len(item) != 2 || json.Unmarshal(item["contract_id"], &contractText) != nil ||
			json.Unmarshal(item[instant], &at) != nil {
			return contractexpiry.Page{}, ErrTrustContractExpiry
		}
		contract, err := sharing.ParseContractID(contractText)
		if err != nil {
			return contractexpiry.Page{}, ErrTrustContractExpiry
		}
		candidate := contractexpiry.Candidate{ContractID: contract, At: at.UTC()}
		page.Items = append(page.Items, candidate)
		page.Next = contractexpiry.Cursor{At: candidate.At, ContractID: candidate.ContractID}
	}
	if page.Done {
		page.Next = contractexpiry.Cursor{}
	}
	if !page.IsValid(after, limit) {
		return contractexpiry.Page{}, ErrTrustContractExpiry
	}
	return page, nil
}

// End prepares the terminal state and locks the audit heads, hashes the
// evidence locally, then finalizes and commits in one bounded transaction. An
// unknown commit outcome is reported and never retried here; the next sweep
// re-reads committed state.
func (store *trustContractEndStore) End(ctx context.Context, installation deployment.ID, contract sharing.ContractID) (changed bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || !contract.IsValid() {
		return false, ErrInvalidTrustContractExpiry
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrTrustContractExpiry, err)
	}
	var ids [5]publicid.ID
	for index := range ids {
		id, err := freshPublicID()
		if err != nil {
			return false, errors.Join(ErrTrustContractExpiry, err)
		}
		ids[index] = id
	}
	change := ids[0]
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
		return false, errors.Join(ErrTrustContractExpiry, beginErr)
	}
	if transaction == nil {
		return false, ErrTrustContractExpiry
	}
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, "5000", "1000", "10000"); err != nil {
		return false, errors.Join(ErrTrustContractExpiry, err)
	}
	var encoded []byte
	if err := transaction.QueryRow(ctx, store.ending.prepareSQL, installation.String(), contract.String(), change.String()).Scan(&encoded); err != nil {
		return false, errors.Join(ErrTrustContractExpiry, err)
	}
	proof, err := decodeTrustContractEndProof(encoded, store.ending.action, contract, change)
	if err != nil {
		return false, err
	}
	if proof.Changed {
		events, err := hashTrustContractEndEvents(proof, store.ending.action, change, ids[1:])
		if err != nil {
			return false, errors.Join(ErrTrustContractExpiry, err)
		}
		var count int
		if err := transaction.QueryRow(ctx, store.ending.finalizeSQL, installation.String(), contract.String(), change.String(), events).Scan(&count); err != nil {
			return false, errors.Join(ErrTrustContractExpiry, err)
		}
		if count != 2 {
			return false, ErrTrustContractExpiry
		}
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrTrustContractExpiry, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return false, errors.Join(ErrTrustContractExpiry, ErrTrustContractExpiryCommitUnknown, err)
	}
	committed = true
	return proof.Changed, nil
}

type trustContractExpiryProof struct {
	Changed          bool                          `json:"changed"`
	TransactionID    string                        `json:"transaction_id"`
	ChangeID         string                        `json:"change_id"`
	ContractID       string                        `json:"contract_id"`
	AggregateKind    string                        `json:"aggregate_kind"`
	AggregateID      string                        `json:"aggregate_id"`
	AggregateVersion int64                         `json:"aggregate_version"`
	Action           string                        `json:"action"`
	Events           []trustContractExpiryEvidence `json:"events"`
}

type trustContractExpiryEvidence struct {
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

func decodeTrustContractEndProof(encoded []byte, action string, contract sharing.ContractID, change publicid.ID) (trustContractExpiryProof, error) {
	if len(encoded) == 0 || len(encoded) > 65536 {
		return trustContractExpiryProof{}, ErrTrustContractExpiry
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &shape); err != nil || shape == nil ||
		string(shape["changed"]) != "true" && string(shape["changed"]) != "false" {
		return trustContractExpiryProof{}, ErrTrustContractExpiry
	}
	var proof trustContractExpiryProof
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil || proof.Events == nil {
		return trustContractExpiryProof{}, ErrTrustContractExpiry
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return trustContractExpiryProof{}, ErrTrustContractExpiry
	}
	if !proof.Changed {
		if len(proof.Events) != 0 || proof.TransactionID != "" || proof.ChangeID != "" || proof.ContractID != "" ||
			proof.AggregateKind != "" || proof.AggregateID != "" || proof.AggregateVersion != 0 || proof.Action != "" {
			return trustContractExpiryProof{}, ErrTrustContractExpiry
		}
		return proof, nil
	}
	transaction, err := strconv.ParseInt(proof.TransactionID, 10, 64)
	if err != nil || transaction <= 0 || proof.ChangeID != change.String() || proof.ContractID != contract.String() ||
		proof.AggregateKind != trustContractExpiryAggregateKind || proof.AggregateID != contract.String() ||
		proof.AggregateVersion <= 1 || proof.Action != action || len(proof.Events) != 2 {
		return trustContractExpiryProof{}, ErrTrustContractExpiry
	}
	for index, event := range proof.Events {
		if !validTrustContractExpiryEvidence(event) {
			return trustContractExpiryProof{}, ErrTrustContractExpiry
		}
		if index == 1 && (event.NetworkID == proof.Events[0].NetworkID || event.StreamID == proof.Events[0].StreamID) {
			return trustContractExpiryProof{}, ErrTrustContractExpiry
		}
	}
	return proof, nil
}

func validTrustContractExpiryEvidence(event trustContractExpiryEvidence) bool {
	workspaceID, workspaceErr := workspace.ParseID(event.WorkspaceID)
	networkID, networkErr := network.ParseID(event.NetworkID)
	if workspaceErr != nil || networkErr != nil {
		return false
	}
	if _, err := network.NewScope(workspaceID, networkID); err != nil {
		return false
	}
	previous, err := hex.DecodeString(event.PreviousHash)
	return err == nil && len(previous) == sha256.Size &&
		event.StreamID > 0 && event.Sequence > 0 && event.NetworkRevision > 0 && event.SharingRevision > 0 &&
		len(event.AuditPayload) > 0 && len(event.AuditPayload) <= 16384 && json.Valid([]byte(event.AuditPayload)) &&
		len(event.OutboxPayload) > 0 && len(event.OutboxPayload) <= 16384 && json.Valid([]byte(event.OutboxPayload)) &&
		event.EventID == "" && event.OutboxID == "" && event.EventHash == ""
}

// hashTrustContractEndEvents binds each event to a fresh event and outbox
// id. The system actor and correlation are zero, as in other reconcilers.
func hashTrustContractEndEvents(proof trustContractExpiryProof, action string, change publicid.ID, ids []publicid.ID) ([]byte, error) {
	if len(ids) != 2*len(proof.Events) {
		return nil, ErrTrustContractExpiry
	}
	aggregateID, err := publicid.Parse(proof.AggregateID)
	if err != nil {
		return nil, ErrTrustContractExpiry
	}
	events := make([]trustContractExpiryEvidence, len(proof.Events))
	copy(events, proof.Events)
	for index := range events {
		event := &events[index]
		previous, err := hex.DecodeString(event.PreviousHash)
		if err != nil || len(previous) != sha256.Size {
			return nil, ErrTrustContractExpiry
		}
		eventID, outboxID := ids[2*index], ids[2*index+1]
		hash, err := audit.HashEvent(audit.EventHashMaterial{
			PreviousHash: [32]byte(previous), EventID: eventID, ChangeID: change,
			AggregateKind: trustContractExpiryAggregateKind, AggregateID: aggregateID, AggregateVersion: proof.AggregateVersion,
			NetworkRevision: event.NetworkRevision, Action: action, Permission: trustContractExpiryPermission,
			AuditPayloadHash:  sha256.Sum256([]byte(event.AuditPayload)),
			OutboxEventClass:  "network.revision.advanced",
			OutboxPayloadHash: sha256.Sum256([]byte(event.OutboxPayload)),
		})
		if err != nil {
			return nil, err
		}
		event.EventID, event.OutboxID, event.EventHash = eventID.String(), outboxID.String(), hex.EncodeToString(hash[:])
	}
	return json.Marshal(events)
}

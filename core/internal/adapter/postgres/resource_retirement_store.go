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
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/resource/retirement"
	"meshtransit.net/core/internal/domain/workspace"
)

var (
	// ErrInvalidResourceRetirement reports unsafe construction or input.
	ErrInvalidResourceRetirement = errors.New("invalid postgres Resource retirement")
	// ErrResourceRetirement classifies a failed discovery or retirement.
	ErrResourceRetirement = errors.New("retire postgres Resource")
	// ErrResourceRetirementCommitUnknown forbids retry until state is re-read.
	ErrResourceRetirementCommitUnknown = errors.New("postgres Resource retirement commit outcome unknown")
)

const (
	listResourceRetirementsSQL     = `SELECT mesh_ops.list_resource_device_removals_v1($1::UUID,$2::TIMESTAMPTZ,$3::UUID,$4::INTEGER)`
	prepareResourceRetirementSQL   = `SELECT mesh_ops.prepare_resource_device_removal_v1($1::UUID,$2::UUID,$3::UUID)`
	finalizeResourceRetirementSQL  = `SELECT mesh_ops.finalize_resource_device_removal_v1($1::UUID,$2::UUID,$3::UUID,$4::JSONB)`
	resourceRetirementAction       = "resource.retired"
	resourceRetirementPermission   = "system.reconcile"
	resourceRetirementAggregate    = "resource"
	resourceRetirementOutboxClass  = "network.revision.advanced"
	resourceRetirementMaximumBytes = 65536
)

// ResourceRetirementStore retires the Resources of removed Devices, as
// queued by the database when the Device left, through a worker pool only.
// It holds no authority cache, sticky transaction or goroutine.
type ResourceRetirementStore struct {
	database outboxDatabase
}

var (
	_ retirement.Candidates = (*ResourceRetirementStore)(nil)
	_ retirement.Retirer    = (*ResourceRetirementStore)(nil)
)

// NewResourceRetirementStore rejects non-worker pools before any effect.
func NewResourceRetirementStore(pool *Pool) (*ResourceRetirementStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, ErrInvalidResourceRetirement
	}
	return &ResourceRetirementStore{database: pool.outboxDatabase}, nil
}

// List reads one keyset page of queued Resources in one read-only
// transaction. Discovery writes no mutation, audit or outbox row.
func (store *ResourceRetirementStore) List(ctx context.Context, installation deployment.ID, after retirement.Cursor, limit int) (result retirement.Page, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || !after.IsValid() || limit < 1 || limit > 128 {
		return retirement.Page{}, ErrInvalidResourceRetirement
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return retirement.Page{}, errors.Join(ErrResourceRetirement, err)
	}
	transaction, beginErr := store.database.Begin(ctx, true)
	committed := false
	if transaction != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
			}
			if resultErr != nil {
				result = retirement.Page{}
			}
		}()
	}
	if beginErr != nil {
		return retirement.Page{}, errors.Join(ErrResourceRetirement, beginErr)
	}
	if transaction == nil {
		return retirement.Page{}, ErrResourceRetirement
	}
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, "3000", "1000", "5000"); err != nil {
		return retirement.Page{}, errors.Join(ErrResourceRetirement, err)
	}
	var afterInstant, afterResource any
	if !after.IsZero() {
		afterInstant, afterResource = after.At, after.ResourceID.String()
	}
	var encoded []byte
	if err := transaction.QueryRow(ctx, listResourceRetirementsSQL, installation.String(), afterInstant, afterResource, limit).Scan(&encoded); err != nil {
		return retirement.Page{}, errors.Join(ErrResourceRetirement, err)
	}
	page, err := decodeResourceRetirementPage(encoded, after, limit)
	if err != nil {
		return retirement.Page{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return retirement.Page{}, errors.Join(ErrResourceRetirement, err)
	}
	committed = true
	return page, nil
}

// decodeResourceRetirementPage reads items of exactly resource_id and
// requested_at; any other key is rejected.
func decodeResourceRetirementPage(encoded []byte, after retirement.Cursor, limit int) (retirement.Page, error) {
	if len(encoded) == 0 || len(encoded) > resourceRetirementMaximumBytes {
		return retirement.Page{}, ErrResourceRetirement
	}
	var record struct {
		Items []map[string]json.RawMessage `json:"items"`
		Done  *bool                        `json:"done"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Items == nil || record.Done == nil || len(record.Items) > limit {
		return retirement.Page{}, ErrResourceRetirement
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return retirement.Page{}, ErrResourceRetirement
	}
	page := retirement.Page{Done: *record.Done, Items: make([]retirement.Candidate, 0, len(record.Items))}
	for _, item := range record.Items {
		var resourceText string
		var at time.Time
		if len(item) != 2 || json.Unmarshal(item["resource_id"], &resourceText) != nil ||
			json.Unmarshal(item["requested_at"], &at) != nil {
			return retirement.Page{}, ErrResourceRetirement
		}
		id, err := resource.ParseID(resourceText)
		if err != nil {
			return retirement.Page{}, ErrResourceRetirement
		}
		candidate := retirement.Candidate{ResourceID: id, At: at.UTC()}
		page.Items = append(page.Items, candidate)
		page.Next = retirement.Cursor{At: candidate.At, ResourceID: candidate.ResourceID}
	}
	if page.Done {
		page.Next = retirement.Cursor{}
	}
	if !page.IsValid(after, limit) {
		return retirement.Page{}, ErrResourceRetirement
	}
	return page, nil
}

// Retire prepares the retirement and locks the audit head, hashes the
// evidence locally, then finalizes and commits in one bounded transaction. An
// unknown commit outcome is reported and never retried here; the next sweep
// re-reads committed state.
func (store *ResourceRetirementStore) Retire(ctx context.Context, installation deployment.ID, id resource.ID) (changed bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || !id.IsValid() {
		return false, ErrInvalidResourceRetirement
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrResourceRetirement, err)
	}
	var ids [3]publicid.ID
	for index := range ids {
		fresh, err := freshPublicID()
		if err != nil {
			return false, errors.Join(ErrResourceRetirement, err)
		}
		ids[index] = fresh
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
		return false, errors.Join(ErrResourceRetirement, beginErr)
	}
	if transaction == nil {
		return false, ErrResourceRetirement
	}
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, "5000", "1000", "10000"); err != nil {
		return false, errors.Join(ErrResourceRetirement, err)
	}
	var encoded []byte
	if err := transaction.QueryRow(ctx, prepareResourceRetirementSQL, installation.String(), id.String(), change.String()).Scan(&encoded); err != nil {
		return false, errors.Join(ErrResourceRetirement, err)
	}
	proof, err := decodeResourceRetirementProof(encoded, id, change)
	if err != nil {
		return false, err
	}
	if proof.Changed {
		event, err := hashResourceRetirementEvent(proof, change, ids[1], ids[2])
		if err != nil {
			return false, errors.Join(ErrResourceRetirement, err)
		}
		var count int
		if err := transaction.QueryRow(ctx, finalizeResourceRetirementSQL, installation.String(), id.String(), change.String(), event).Scan(&count); err != nil {
			return false, errors.Join(ErrResourceRetirement, err)
		}
		if count != 1 {
			return false, ErrResourceRetirement
		}
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrResourceRetirement, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return false, errors.Join(ErrResourceRetirement, ErrResourceRetirementCommitUnknown, err)
	}
	committed = true
	if proof.Blocked {
		// Committed: the queue row now waits before it is offered again.
		return false, retirement.ErrInUse
	}
	return proof.Changed, nil
}

type resourceRetirementProof struct {
	Changed          bool                        `json:"changed"`
	Blocked          bool                        `json:"blocked"`
	TransactionID    string                      `json:"transaction_id"`
	ChangeID         string                      `json:"change_id"`
	ResourceID       string                      `json:"resource_id"`
	AggregateVersion int64                       `json:"aggregate_version"`
	Event            *resourceRetirementEvidence `json:"event"`
	Events           []json.RawMessage           `json:"events"`
}

type resourceRetirementEvidence struct {
	WorkspaceID     string `json:"workspace_id"`
	NetworkID       string `json:"network_id"`
	StreamID        int64  `json:"stream_id"`
	Sequence        int64  `json:"sequence"`
	PreviousHash    string `json:"previous_hash"`
	NetworkRevision int64  `json:"network_revision"`
	AuditPayload    string `json:"audit_payload"`
	OutboxPayload   string `json:"outbox_payload"`
	EventID         string `json:"event_id,omitempty"`
	OutboxID        string `json:"outbox_id,omitempty"`
	EventHash       string `json:"event_hash,omitempty"`
}

// decodeResourceRetirementProof accepts exactly the unchanged answer, or one
// retirement of the requested Resource under this change with one event.
func decodeResourceRetirementProof(encoded []byte, id resource.ID, change publicid.ID) (resourceRetirementProof, error) {
	if len(encoded) == 0 || len(encoded) > resourceRetirementMaximumBytes {
		return resourceRetirementProof{}, ErrResourceRetirement
	}
	var proof resourceRetirementProof
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return resourceRetirementProof{}, ErrResourceRetirement
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return resourceRetirementProof{}, ErrResourceRetirement
	}
	if !proof.Changed {
		if proof.Events == nil || len(proof.Events) != 0 || proof.Event != nil || proof.TransactionID != "" ||
			proof.ChangeID != "" || proof.ResourceID != "" || proof.AggregateVersion != 0 {
			return resourceRetirementProof{}, ErrResourceRetirement
		}
		return proof, nil
	}
	if proof.Blocked {
		return resourceRetirementProof{}, ErrResourceRetirement
	}
	transaction, err := strconv.ParseInt(proof.TransactionID, 10, 64)
	if err != nil || transaction <= 0 || proof.ChangeID != change.String() || proof.ResourceID != id.String() ||
		proof.AggregateVersion <= 1 || proof.Events != nil || proof.Event == nil ||
		!validResourceRetirementEvidence(*proof.Event) {
		return resourceRetirementProof{}, ErrResourceRetirement
	}
	return proof, nil
}

func validResourceRetirementEvidence(event resourceRetirementEvidence) bool {
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
		event.StreamID > 0 && event.Sequence > 0 && event.NetworkRevision > 0 &&
		len(event.AuditPayload) > 0 && len(event.AuditPayload) <= 16384 && json.Valid([]byte(event.AuditPayload)) &&
		len(event.OutboxPayload) > 0 && len(event.OutboxPayload) <= 16384 && json.Valid([]byte(event.OutboxPayload)) &&
		event.EventID == "" && event.OutboxID == "" && event.EventHash == ""
}

// hashResourceRetirementEvent binds the event to fresh event and outbox ids.
// The system actor and correlation are zero, as in other reconcilers.
func hashResourceRetirementEvent(proof resourceRetirementProof, change, eventID, outboxID publicid.ID) ([]byte, error) {
	if proof.Event == nil {
		return nil, ErrResourceRetirement
	}
	aggregateID, err := publicid.Parse(proof.ResourceID)
	if err != nil {
		return nil, ErrResourceRetirement
	}
	event := *proof.Event
	previous, err := hex.DecodeString(event.PreviousHash)
	if err != nil || len(previous) != sha256.Size {
		return nil, ErrResourceRetirement
	}
	hash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: [32]byte(previous), EventID: eventID, ChangeID: change,
		AggregateKind: resourceRetirementAggregate, AggregateID: aggregateID, AggregateVersion: proof.AggregateVersion,
		NetworkRevision: event.NetworkRevision, Action: resourceRetirementAction, Permission: resourceRetirementPermission,
		AuditPayloadHash:  sha256.Sum256([]byte(event.AuditPayload)),
		OutboxEventClass:  resourceRetirementOutboxClass,
		OutboxPayloadHash: sha256.Sum256([]byte(event.OutboxPayload)),
	})
	if err != nil {
		return nil, err
	}
	event.EventID, event.OutboxID, event.EventHash = eventID.String(), outboxID.String(), hex.EncodeToString(hash[:])
	return json.Marshal(event)
}

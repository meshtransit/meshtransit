package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"time"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/primaryelection"
	"meshtransit.net/core/internal/domain/publicid"
)

var (
	// ErrInvalidExitPoolPrimary reports unsafe construction or input.
	ErrInvalidExitPoolPrimary = errors.New("invalid postgres Exit Pool election")
	// ErrExitPoolPrimary classifies a failed read or election.
	ErrExitPoolPrimary = errors.New("elect postgres Exit Pool primary")
	// ErrExitPoolPrimaryCommitUnknown forbids retry until state is re-read.
	ErrExitPoolPrimaryCommitUnknown = errors.New("postgres Exit Pool election commit outcome unknown")
)

const (
	listExitPoolElectionsSQL   = `SELECT mesh_ops.list_exit_pool_elections_v2($1::UUID,$2::UUID,$3::INTEGER)`
	prepareExitPoolServingSQL  = `SELECT mesh_ops.prepare_exit_pool_serving_v1($1::UUID,$2::UUID,$3::BIGINT,$4::UUID[],$5::TEXT,$6::UUID)`
	finalizeExitPoolServingSQL = `SELECT mesh_ops.finalize_exit_pool_serving_v1($1::UUID,$2::UUID,$3::UUID,$4::TEXT,$5::JSONB)`
	exitPoolServingAction      = "exit_pool.serving_changed"
	exitPoolServingAggregate   = "exit_pool_serving"
	prepareExitPoolPrimarySQL  = `SELECT mesh_ops.prepare_exit_pool_primary_v1($1::UUID,$2::UUID,$3::BIGINT,$4::UUID,$5::TEXT,$6::UUID)`
	finalizeExitPoolPrimarySQL = `SELECT mesh_ops.finalize_exit_pool_primary_v1($1::UUID,$2::UUID,$3::UUID,$4::TEXT,$5::JSONB)`
	exitPoolPrimaryAction      = "exit_pool.primary_changed"
	exitPoolPrimaryAggregate   = "exit_pool_primary"
)

// ExitPoolPrimaryStore reads Exit Pools to elect for and records their
// primaries, through a worker pool only. It holds no cache, sticky
// transaction or goroutine.
type ExitPoolPrimaryStore struct {
	database outboxDatabase
}

var (
	_ primaryelection.Facts           = (*ExitPoolPrimaryStore)(nil)
	_ primaryelection.Recorder        = (*ExitPoolPrimaryStore)(nil)
	_ primaryelection.ServingRecorder = (*ExitPoolPrimaryStore)(nil)
)

// NewExitPoolPrimaryStore rejects non-worker pools before any effect.
func NewExitPoolPrimaryStore(pool *Pool) (*ExitPoolPrimaryStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, ErrInvalidExitPoolPrimary
	}
	return &ExitPoolPrimaryStore{database: pool.outboxDatabase}, nil
}

// List reads one page of pools with exit nodes after a pool in one read-only
// transaction.
func (store *ExitPoolPrimaryStore) List(ctx context.Context, installation deployment.ID, after string, limit int,
) (result primaryelection.Page, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || limit < 1 || limit > 64 {
		return primaryelection.Page{}, ErrInvalidExitPoolPrimary
	}
	var afterPool any
	if after != "" {
		id, err := exitpool.ParseID(after)
		if err != nil || id.String() != after {
			return primaryelection.Page{}, ErrInvalidExitPoolPrimary
		}
		afterPool = after
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return primaryelection.Page{}, errors.Join(ErrExitPoolPrimary, err)
	}
	transaction, beginErr := store.database.Begin(ctx, true)
	committed := false
	if transaction != nil {
		defer func() {
			if !committed {
				resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
			}
			if resultErr != nil {
				result = primaryelection.Page{}
			}
		}()
	}
	if beginErr != nil {
		return primaryelection.Page{}, errors.Join(ErrExitPoolPrimary, beginErr)
	}
	if transaction == nil {
		return primaryelection.Page{}, ErrExitPoolPrimary
	}
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, "3000", "1000", "5000"); err != nil {
		return primaryelection.Page{}, errors.Join(ErrExitPoolPrimary, err)
	}
	var encoded []byte
	if err := transaction.QueryRow(ctx, listExitPoolElectionsSQL, installation.String(), afterPool, limit).
		Scan(&encoded); err != nil {
		return primaryelection.Page{}, errors.Join(ErrExitPoolPrimary, err)
	}
	page, err := decodeExitPoolElectionPage(encoded, after, limit)
	if err != nil {
		return primaryelection.Page{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return primaryelection.Page{}, errors.Join(ErrExitPoolPrimary, err)
	}
	committed = true
	return page, nil
}

type exitPoolElectionRecord struct {
	PoolID      string                   `json:"pool_id"`
	WorkspaceID string                   `json:"workspace_id"`
	NetworkID   string                   `json:"network_id"`
	Failback    *bool                    `json:"failback"`
	Primary     *string                  `json:"primary_device_id"`
	Generation  *int64                   `json:"generation"`
	Nodes       []exitPoolElectionMember `json:"nodes"`
	// Schema 210: whether the pool is spread, its serving set, the set's
	// generation and when it last changed (null before the first).
	Spread            *bool      `json:"spread"`
	Serving           []string   `json:"serving"`
	ServingGeneration *int64     `json:"serving_generation"`
	ServingChangedAt  *time.Time `json:"serving_changed_at"`
	ServingReason     *string    `json:"serving_reason"`
	ServingPrevious   []string   `json:"serving_previous"`
}

type exitPoolElectionMember struct {
	DeviceID       string `json:"device_id"`
	Priority       *int   `json:"priority"`
	State          string `json:"state"`
	Live           *bool  `json:"live"`
	WorkspaceOwned *bool  `json:"workspace_owned"`
	Offered        *bool  `json:"offered"`
}

// decodeExitPoolElectionPage accepts exactly the documented shape: pools in
// increasing order after after, exit nodes in priority order.
func decodeExitPoolElectionPage(encoded []byte, after string, limit int) (primaryelection.Page, error) {
	if len(encoded) == 0 || len(encoded) > sitePrimaryMaximumBytes {
		return primaryelection.Page{}, ErrExitPoolPrimary
	}
	var record struct {
		Items []exitPoolElectionRecord `json:"items"`
		Done  *bool                    `json:"done"`
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil || record.Items == nil || record.Done == nil ||
		len(record.Items) > limit || (!*record.Done && len(record.Items) != limit) {
		return primaryelection.Page{}, ErrExitPoolPrimary
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return primaryelection.Page{}, ErrExitPoolPrimary
	}
	page := primaryelection.Page{Done: *record.Done, Groups: make([]primaryelection.GroupFacts, 0, len(record.Items))}
	previous := after
	for _, item := range record.Items {
		// Canonical UUID text sorts as the UUIDs do.
		facts, ok := decodeExitPoolElection(item)
		if !ok || (previous != "" && facts.Group <= previous) {
			return primaryelection.Page{}, ErrExitPoolPrimary
		}
		previous = facts.Group
		page.Groups = append(page.Groups, facts)
	}
	return page, nil
}

func decodeExitPoolElection(item exitPoolElectionRecord) (primaryelection.GroupFacts, bool) {
	id, err := exitpool.ParseID(item.PoolID)
	if err != nil || id.String() != item.PoolID || item.Failback == nil || item.Generation == nil ||
		*item.Generation < 0 || len(item.Nodes) == 0 || len(item.Nodes) > exitpool.MaximumNodesPerPool ||
		item.WorkspaceID == "" || item.NetworkID == "" {
		return primaryelection.GroupFacts{}, false
	}
	if item.Spread == nil || item.Serving == nil || len(item.Serving) > exitpool.MaximumNodesPerPool ||
		item.ServingGeneration == nil || *item.ServingGeneration < 0 ||
		(*item.ServingGeneration > 0) != (item.ServingChangedAt != nil) {
		return primaryelection.GroupFacts{}, false
	}
	facts := primaryelection.GroupFacts{Group: item.PoolID, Failback: *item.Failback, Generation: *item.Generation,
		Members: make([]primaryelection.MemberFacts, 0, len(item.Nodes)), Spread: *item.Spread,
		ServingGeneration: *item.ServingGeneration}
	if item.ServingChangedAt != nil {
		facts.ServingChangedAt = item.ServingChangedAt.UTC()
	}
	if (item.ServingReason != nil) != (*item.ServingGeneration > 0) || item.ServingPrevious == nil ||
		len(item.ServingPrevious) > exitpool.MaximumNodesPerPool {
		return primaryelection.GroupFacts{}, false
	}
	if item.ServingReason != nil {
		facts.ServingReason = *item.ServingReason
	}
	for _, text := range item.ServingPrevious {
		device, err := node.ParseID(text)
		if err != nil {
			return primaryelection.GroupFacts{}, false
		}
		facts.ServingPrevious = append(facts.ServingPrevious, device)
	}
	for _, text := range item.Serving {
		device, err := node.ParseID(text)
		if err != nil || slices.Contains(facts.Serving, device) {
			return primaryelection.GroupFacts{}, false
		}
		facts.Serving = append(facts.Serving, device)
	}
	if item.Primary != nil {
		if facts.Primary, err = node.ParseID(*item.Primary); err != nil {
			return primaryelection.GroupFacts{}, false
		}
	}
	seen := map[node.ID]struct{}{}
	for index, member := range item.Nodes {
		device, err := node.ParseID(member.DeviceID)
		if err != nil || member.Priority == nil || member.Live == nil || member.WorkspaceOwned == nil ||
			member.Offered == nil || (member.State != "active" && member.State != "draining") {
			return primaryelection.GroupFacts{}, false
		}
		if _, repeated := seen[device]; repeated {
			return primaryelection.GroupFacts{}, false
		}
		seen[device] = struct{}{}
		if index > 0 {
			before := item.Nodes[index-1]
			if *before.Priority > *member.Priority ||
				(*before.Priority == *member.Priority && before.DeviceID >= member.DeviceID) {
				return primaryelection.GroupFacts{}, false
			}
		}
		facts.Members = append(facts.Members, primaryelection.MemberFacts{Device: device, Priority: *member.Priority,
			Draining: member.State == "draining",
			Eligible: *member.Live && *member.WorkspaceOwned && *member.Offered})
	}
	return facts, true
}

// Record prepares the decision and locks the audit head, hashes the evidence
// locally, then finalizes and commits in one bounded transaction. False
// means the decision was made on an older state or changes nothing. An
// unknown commit outcome is reported and never retried here; the next sweep
// re-reads committed state.
func (store *ExitPoolPrimaryStore) Record(ctx context.Context, installation deployment.ID,
	decision primaryelection.Decision,
) (bool, error) {
	if !validElectionReason(decision.Reason) {
		return false, ErrInvalidExitPoolPrimary
	}
	var device any
	if decision.Primary.IsValid() {
		device = decision.Primary.String()
	}
	return store.record(ctx, installation, exitPoolElection{
		group: decision.Group, expectedGeneration: decision.ExpectedGeneration, reason: decision.Reason,
		prepareSQL: prepareExitPoolPrimarySQL, finalizeSQL: finalizeExitPoolPrimarySQL, choice: device,
		aggregate: exitPoolPrimaryAggregate, action: exitPoolPrimaryAction,
	})
}

// RecordServing records a spread pool's serving set as Record records its
// primary: audited as exit_pool.serving_changed.
func (store *ExitPoolPrimaryStore) RecordServing(ctx context.Context, installation deployment.ID,
	decision primaryelection.ServingDecision,
) (bool, error) {
	if !exitpool.IsValidServingReason(decision.Reason) || len(decision.Devices) > exitpool.MaximumNodesPerPool {
		return false, ErrInvalidExitPoolPrimary
	}
	devices := make([]string, 0, len(decision.Devices))
	for _, device := range decision.Devices {
		if !device.IsValid() || slices.Contains(devices, device.String()) {
			return false, ErrInvalidExitPoolPrimary
		}
		devices = append(devices, device.String())
	}
	return store.record(ctx, installation, exitPoolElection{
		group: decision.Group, expectedGeneration: decision.ExpectedGeneration, reason: decision.Reason,
		prepareSQL: prepareExitPoolServingSQL, finalizeSQL: finalizeExitPoolServingSQL, choice: devices,
		aggregate: exitPoolServingAggregate, action: exitPoolServingAction,
	})
}

// exitPoolElection is one primary or serving set decision to record.
type exitPoolElection struct {
	group              string
	expectedGeneration int64
	reason             string
	prepareSQL         string
	finalizeSQL        string
	// choice is the prepare argument after the generation: the primary's
	// Device or the serving set's Devices.
	choice            any
	aggregate, action string
}

func (store *ExitPoolPrimaryStore) record(ctx context.Context, installation deployment.ID,
	election exitPoolElection,
) (changed bool, resultErr error) {
	poolID, poolErr := exitpool.ParseID(election.group)
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || poolErr != nil ||
		poolID.String() != election.group || election.expectedGeneration < 0 {
		return false, ErrInvalidExitPoolPrimary
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrExitPoolPrimary, err)
	}
	var ids [3]publicid.ID
	for index := range ids {
		fresh, err := freshPublicID()
		if err != nil {
			return false, errors.Join(ErrExitPoolPrimary, err)
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
		return false, errors.Join(ErrExitPoolPrimary, beginErr)
	}
	if transaction == nil {
		return false, ErrExitPoolPrimary
	}
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, "5000", "1000", "10000"); err != nil {
		return false, errors.Join(ErrExitPoolPrimary, err)
	}
	var encoded []byte
	if err := transaction.QueryRow(ctx, election.prepareSQL, installation.String(), election.group,
		election.expectedGeneration, election.choice, election.reason, change.String()).Scan(&encoded); err != nil {
		return false, errors.Join(ErrExitPoolPrimary, err)
	}
	proof, err := decodeExitPoolPrimaryProof(encoded, election.group, election.expectedGeneration, change)
	if err != nil {
		return false, err
	}
	if !proof.Changed {
		return false, nil // rolled back by the deferred function
	}
	event, err := hashExitPoolElectionEvent(proof, change, ids[1], ids[2], election.aggregate, election.action)
	if err != nil {
		return false, errors.Join(ErrExitPoolPrimary, err)
	}
	var count int
	if err := transaction.QueryRow(ctx, election.finalizeSQL, installation.String(), election.group,
		change.String(), election.reason, event).Scan(&count); err != nil {
		return false, errors.Join(ErrExitPoolPrimary, err)
	}
	if count != 1 {
		return false, ErrExitPoolPrimary
	}
	if err := ctx.Err(); err != nil {
		return false, errors.Join(ErrExitPoolPrimary, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return false, errors.Join(ErrExitPoolPrimary, ErrExitPoolPrimaryCommitUnknown, err)
	}
	committed = true
	return true, nil
}

type exitPoolPrimaryProof struct {
	Changed          bool                        `json:"changed"`
	TransactionID    string                      `json:"transaction_id"`
	ChangeID         string                      `json:"change_id"`
	PoolID           string                      `json:"pool_id"`
	Generation       int64                       `json:"generation"`
	AggregateVersion int64                       `json:"aggregate_version"`
	Event            *resourceRetirementEvidence `json:"event"`
}

// decodeExitPoolPrimaryProof accepts exactly the unchanged answer, or one
// election of the requested pool under this change, one generation on.
func decodeExitPoolPrimaryProof(encoded []byte, group string, expectedGeneration int64, change publicid.ID,
) (exitPoolPrimaryProof, error) {
	if len(encoded) == 0 || len(encoded) > resourceRetirementMaximumBytes {
		return exitPoolPrimaryProof{}, ErrExitPoolPrimary
	}
	var proof exitPoolPrimaryProof
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return exitPoolPrimaryProof{}, ErrExitPoolPrimary
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return exitPoolPrimaryProof{}, ErrExitPoolPrimary
	}
	if !proof.Changed {
		if proof.Event != nil || proof.TransactionID != "" || proof.ChangeID != "" || proof.PoolID != "" ||
			proof.Generation != 0 || proof.AggregateVersion != 0 {
			return exitPoolPrimaryProof{}, ErrExitPoolPrimary
		}
		return proof, nil
	}
	transaction, err := strconv.ParseInt(proof.TransactionID, 10, 64)
	if err != nil || transaction <= 0 || proof.ChangeID != change.String() || proof.PoolID != group ||
		proof.Generation != expectedGeneration+1 || proof.AggregateVersion < 1 || proof.Event == nil ||
		!validResourceRetirementEvidence(*proof.Event) {
		return exitPoolPrimaryProof{}, ErrExitPoolPrimary
	}
	return proof, nil
}

// hashExitPoolElectionEvent binds the event to fresh event and outbox ids.
// The system actor and correlation are zero, as in other reconcilers.
func hashExitPoolElectionEvent(proof exitPoolPrimaryProof, change, eventID, outboxID publicid.ID,
	aggregate, action string) ([]byte, error) {
	if proof.Event == nil {
		return nil, ErrExitPoolPrimary
	}
	aggregateID, err := publicid.Parse(proof.PoolID)
	if err != nil {
		return nil, ErrExitPoolPrimary
	}
	event := *proof.Event
	previous, err := hex.DecodeString(event.PreviousHash)
	if err != nil || len(previous) != sha256.Size {
		return nil, ErrExitPoolPrimary
	}
	hash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: [32]byte(previous), EventID: eventID, ChangeID: change,
		AggregateKind: aggregate, AggregateID: aggregateID, AggregateVersion: proof.AggregateVersion,
		NetworkRevision: event.NetworkRevision, Action: action, Permission: sitePrimaryPermission,
		AuditPayloadHash:  sha256.Sum256([]byte(event.AuditPayload)),
		OutboxEventClass:  sitePrimaryOutboxClass,
		OutboxPayloadHash: sha256.Sum256([]byte(event.OutboxPayload)),
	})
	if err != nil {
		return nil, err
	}
	event.EventID, event.OutboxID, event.EventHash = eventID.String(), outboxID.String(), hex.EncodeToString(hash[:])
	return json.Marshal(event)
}

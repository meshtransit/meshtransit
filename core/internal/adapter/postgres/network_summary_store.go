package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/networksummary"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

var (
	// ErrInvalidNetworkSummary reports unsafe construction or input.
	ErrInvalidNetworkSummary = errors.New("invalid postgres network summary")
	// ErrNetworkSummary classifies a failed claim, count or store.
	ErrNetworkSummary = errors.New("postgres network summary")
)

const (
	claimNetworkSummarySQL   = `SELECT mesh_ops.claim_network_summary_work_v1($1::UUID,$2::UUID,$3::INTEGER,$4::INTEGER)::TEXT`
	computeNetworkSummarySQL = `SELECT mesh_ops.compute_network_summary_v1($1::UUID,$2::UUID,$3::UUID)::TEXT`
	storeNetworkSummarySQL   = `SELECT mesh_ops.store_network_summary_v1($1::UUID,$2::UUID,$3::JSONB,$4::INTEGER,$5::INTEGER)`
	releaseNetworkSummarySQL = `SELECT mesh_ops.release_network_summary_claim_v1($1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::INTEGER)`
	networkSummaryLagSQL     = `SELECT mesh_ops.network_summary_lag_v1($1::UUID)::TEXT`
	foldNetworkSummarySQL    = `SELECT mesh_ops.fold_network_summary_marks_v1($1::INTEGER)`
	networkSummaryMaxFold    = 50000
	networkSummaryMaxBatch   = 64
	networkSummaryMaxJSON    = 1 << 20
)

// NetworkSummaryStore runs the summary worker's statements through a worker
// pool. Counting runs in a REPEATABLE READ READ ONLY transaction, so the
// marker and every count come from one snapshot; claims and stores are
// short transactions of their own.
type NetworkSummaryStore struct{ database outboxDatabase }

var _ networksummary.Store = (*NetworkSummaryStore)(nil)

// NewNetworkSummaryStore rejects non-worker pools before any effect.
func NewNetworkSummaryStore(pool *Pool) (*NetworkSummaryStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, ErrInvalidNetworkSummary
	}
	return &NetworkSummaryStore{database: pool.outboxDatabase}, nil
}

// Fold moves up to limit change marks into the queue in one short
// transaction; 0 when another worker is folding.
func (store *NetworkSummaryStore) Fold(ctx context.Context, limit int) (int, error) {
	if ctx == nil || store == nil || store.database == nil || limit < 1 || limit > networkSummaryMaxFold {
		return 0, ErrInvalidNetworkSummary
	}
	var folded int
	err := store.inTransaction(ctx, false, false, func(transaction outboxTransaction) error {
		return transaction.QueryRow(ctx, foldNetworkSummarySQL, limit).Scan(&folded)
	})
	if err == nil && (folded < 0 || folded > limit) {
		return 0, ErrNetworkSummary
	}
	return folded, err
}

// Claim takes up to limit due Networks for lease.
func (store *NetworkSummaryStore) Claim(ctx context.Context, installation deployment.ID, worker publicid.ID,
	limit int, lease time.Duration) ([]network.Scope, error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || !worker.IsValid() ||
		limit < 1 || limit > networkSummaryMaxBatch || lease < 5*time.Second || lease > 5*time.Minute {
		return nil, ErrInvalidNetworkSummary
	}
	var encoded string
	err := store.inTransaction(ctx, false, false, func(transaction outboxTransaction) error {
		return transaction.QueryRow(ctx, claimNetworkSummarySQL, installation.String(), worker.String(), limit,
			int(lease/time.Second)).Scan(&encoded)
	})
	if err != nil {
		return nil, err
	}
	var record struct {
		Items []struct {
			WorkspaceID string `json:"workspace_id"`
			NetworkID   string `json:"network_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal([]byte(encoded), &record); err != nil || record.Items == nil || len(record.Items) > limit {
		return nil, ErrNetworkSummary
	}
	scopes := make([]network.Scope, 0, len(record.Items))
	for _, item := range record.Items {
		workspaceID, workspaceErr := workspace.ParseID(item.WorkspaceID)
		networkID, networkErr := network.ParseID(item.NetworkID)
		scope, scopeErr := network.NewScope(workspaceID, networkID)
		if workspaceErr != nil || networkErr != nil || scopeErr != nil {
			return nil, ErrNetworkSummary
		}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

type networkSummaryPeerRecord struct {
	Direction       string `json:"direction"`
	PeerWorkspaceID int64  `json:"peer_workspace_id"`
	PeerNetworkID   int64  `json:"peer_network_id"`
	Active          int    `json:"active"`
	Waiting         int    `json:"waiting"`
}

type networkSummaryRecord struct {
	WorkspaceID       int64                      `json:"workspace_id"`
	NetworkID         int64                      `json:"network_id"`
	NetworkRevision   int64                      `json:"network_revision"`
	DirtyGeneration   int64                      `json:"dirty_generation"`
	EvaluatedAt       time.Time                  `json:"evaluated_at"`
	IPv4Prefix        *string                    `json:"ipv4_prefix"`
	AddressesCapacity *int64                     `json:"addresses_capacity"`
	AddressesInUse    int64                      `json:"addresses_in_use"`
	AddressesHeld     int64                      `json:"addresses_held"`
	ActiveDevices     int64                      `json:"active_devices"`
	RuleCount         int64                      `json:"rule_count"`
	PolicyRevision    int64                      `json:"policy_revision"`
	PolicyPublishedAt *time.Time                 `json:"policy_published_at"`
	SharesOutActive   int                        `json:"shares_out_active"`
	SharesInActive    int                        `json:"shares_in_active"`
	OffersWaiting     int                        `json:"offers_waiting"`
	PendingApprovals  int                        `json:"pending_approvals"`
	Sites             int                        `json:"sites"`
	Clusters          int                        `json:"kubernetes_clusters"`
	RecomputeAt       *time.Time                 `json:"recompute_at"`
	Peers             []networkSummaryPeerRecord `json:"peers"`
}

// Compute counts one Network in one snapshot; false when it is not a live
// Network of this installation.
func (store *NetworkSummaryStore) Compute(ctx context.Context, installation deployment.ID,
	scope network.Scope) (networksummary.Summary, bool, error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || !scope.IsValid() {
		return networksummary.Summary{}, false, ErrInvalidNetworkSummary
	}
	var encoded *string
	// One REPEATABLE READ snapshot: the marker and every count agree.
	err := store.inTransaction(ctx, true, true, func(transaction outboxTransaction) error {
		return transaction.QueryRow(ctx, computeNetworkSummarySQL, installation.String(),
			scope.WorkspaceID().String(), scope.NetworkID().String()).Scan(&encoded)
	})
	if err != nil {
		return networksummary.Summary{}, false, err
	}
	if encoded == nil {
		return networksummary.Summary{}, false, nil
	}
	summary, err := decodeNetworkSummary(*encoded)
	if err != nil {
		return networksummary.Summary{}, false, err
	}
	return summary, true, nil
}

func decodeNetworkSummary(encoded string) (networksummary.Summary, error) {
	var record networkSummaryRecord
	if err := decodeStrictJSON(encoded, networkSummaryMaxJSON, &record); err != nil {
		return networksummary.Summary{}, errors.Join(ErrNetworkSummary, err)
	}
	summary := networksummary.Summary{
		WorkspaceID: record.WorkspaceID, NetworkID: record.NetworkID, NetworkRevision: record.NetworkRevision,
		DirtyGeneration: record.DirtyGeneration, EvaluatedAt: record.EvaluatedAt.UTC(),
		AddressesInUse: record.AddressesInUse, AddressesHeld: record.AddressesHeld,
		ActiveDevices: record.ActiveDevices, RuleCount: record.RuleCount, PolicyRevision: record.PolicyRevision,
		SharesOutActive: record.SharesOutActive, SharesInActive: record.SharesInActive,
		OffersWaiting: record.OffersWaiting, PendingApprovals: record.PendingApprovals, Sites: record.Sites,
		KubernetesClusters: record.Clusters,
	}
	if (record.IPv4Prefix == nil) != (record.AddressesCapacity == nil) {
		return networksummary.Summary{}, ErrNetworkSummary
	}
	if record.IPv4Prefix != nil {
		prefix, err := netip.ParsePrefix(*record.IPv4Prefix)
		if err != nil || prefix != prefix.Masked() {
			return networksummary.Summary{}, ErrNetworkSummary
		}
		summary.IPv4Prefix, summary.AddressesCapacity = prefix, *record.AddressesCapacity
	}
	if record.PolicyPublishedAt != nil {
		summary.PolicyPublishedAt = record.PolicyPublishedAt.UTC()
	}
	if record.RecomputeAt != nil {
		summary.RecomputeAt = record.RecomputeAt.UTC()
	}
	for _, peer := range record.Peers {
		summary.Peers = append(summary.Peers, networksummary.Peer{Direction: peer.Direction,
			PeerWorkspaceID: peer.PeerWorkspaceID, PeerNetworkID: peer.PeerNetworkID,
			Active: peer.Active, Waiting: peer.Waiting})
	}
	if err := summary.Validate(); err != nil {
		return networksummary.Summary{}, errors.Join(ErrNetworkSummary, err)
	}
	return summary, nil
}

func encodeNetworkSummary(summary networksummary.Summary) ([]byte, error) {
	record := networkSummaryRecord{
		WorkspaceID: summary.WorkspaceID, NetworkID: summary.NetworkID, NetworkRevision: summary.NetworkRevision,
		DirtyGeneration: summary.DirtyGeneration, EvaluatedAt: summary.EvaluatedAt,
		AddressesInUse: summary.AddressesInUse, AddressesHeld: summary.AddressesHeld,
		ActiveDevices: summary.ActiveDevices, RuleCount: summary.RuleCount, PolicyRevision: summary.PolicyRevision,
		SharesOutActive: summary.SharesOutActive, SharesInActive: summary.SharesInActive,
		OffersWaiting: summary.OffersWaiting, PendingApprovals: summary.PendingApprovals, Sites: summary.Sites,
		Clusters: summary.KubernetesClusters, Peers: []networkSummaryPeerRecord{},
	}
	if summary.IPv4Prefix.IsValid() {
		prefix, capacity := summary.IPv4Prefix.String(), summary.AddressesCapacity
		record.IPv4Prefix, record.AddressesCapacity = &prefix, &capacity
	}
	if !summary.PolicyPublishedAt.IsZero() {
		at := summary.PolicyPublishedAt
		record.PolicyPublishedAt = &at
	}
	if !summary.RecomputeAt.IsZero() {
		at := summary.RecomputeAt
		record.RecomputeAt = &at
	}
	for _, peer := range summary.Peers {
		record.Peers = append(record.Peers, networkSummaryPeerRecord{Direction: peer.Direction,
			PeerWorkspaceID: peer.PeerWorkspaceID, PeerNetworkID: peer.PeerNetworkID,
			Active: peer.Active, Waiting: peer.Waiting})
	}
	return json.Marshal(record)
}

// Save stores the summary if newer and releases this worker's claim.
func (store *NetworkSummaryStore) Save(ctx context.Context, installation deployment.ID, worker publicid.ID,
	summary networksummary.Summary, took, spacing time.Duration) (bool, error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || !worker.IsValid() ||
		took < 0 || spacing < 0 || spacing > 10*time.Minute {
		return false, ErrInvalidNetworkSummary
	}
	if err := summary.Validate(); err != nil {
		return false, errors.Join(ErrInvalidNetworkSummary, err)
	}
	payload, err := encodeNetworkSummary(summary)
	if err != nil {
		return false, errors.Join(ErrNetworkSummary, err)
	}
	tookMilliseconds := min(took.Milliseconds(), math.MaxInt32)
	var newer bool
	err = store.inTransaction(ctx, false, false, func(transaction outboxTransaction) error {
		return transaction.QueryRow(ctx, storeNetworkSummarySQL, installation.String(), worker.String(), string(payload),
			int(tookMilliseconds), int(spacing.Milliseconds())).Scan(&newer)
	})
	return newer, err
}

// Release gives a claim back; the Network is due again after retry.
func (store *NetworkSummaryStore) Release(ctx context.Context, installation deployment.ID, worker publicid.ID,
	scope network.Scope, retry time.Duration) error {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() || !worker.IsValid() ||
		!scope.IsValid() || retry < 0 || retry > 10*time.Minute {
		return ErrInvalidNetworkSummary
	}
	return store.inTransaction(ctx, false, false, func(transaction outboxTransaction) error {
		return transaction.Exec(ctx, releaseNetworkSummarySQL, installation.String(), worker.String(),
			scope.WorkspaceID().String(), scope.NetworkID().String(), int(retry.Milliseconds()))
	})
}

// Lag reads how many Networks wait and the age of the oldest change.
func (store *NetworkSummaryStore) Lag(ctx context.Context, installation deployment.ID) (networksummary.Lag, error) {
	if ctx == nil || store == nil || store.database == nil || !installation.IsValid() {
		return networksummary.Lag{}, ErrInvalidNetworkSummary
	}
	var encoded string
	err := store.inTransaction(ctx, true, false, func(transaction outboxTransaction) error {
		return transaction.QueryRow(ctx, networkSummaryLagSQL, installation.String()).Scan(&encoded)
	})
	if err != nil {
		return networksummary.Lag{}, err
	}
	var record struct {
		Pending int64   `json:"pending"`
		Marks   int64   `json:"marks"`
		Oldest  float64 `json:"oldest_seconds"`
	}
	if err := json.Unmarshal([]byte(encoded), &record); err != nil || record.Pending < 0 || record.Oldest < 0 ||
		record.Marks < 0 {
		return networksummary.Lag{}, ErrNetworkSummary
	}
	return networksummary.Lag{Pending: record.Pending, Marks: record.Marks,
		Oldest: time.Duration(record.Oldest * float64(time.Second))}, nil
}

func (store *NetworkSummaryStore) inTransaction(ctx context.Context, readOnly, repeatable bool,
	run func(outboxTransaction) error) (resultErr error) {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrNetworkSummary, err)
	}
	transaction, err := store.database.Begin(ctx, readOnly)
	if err != nil {
		return errors.Join(ErrNetworkSummary, err)
	}
	if transaction == nil {
		return ErrNetworkSummary
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
		}
	}()
	if repeatable {
		// Before any query: the snapshot is taken at the first one.
		if err := transaction.Exec(ctx, repeatableReadTransactionSQL); err != nil {
			return errors.Join(ErrNetworkSummary, err)
		}
	}
	timeout := postgresTimeout(25 * time.Second)
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, timeout, "2000", timeout); err != nil {
		return errors.Join(ErrNetworkSummary, err)
	}
	if err := run(transaction); err != nil {
		return errors.Join(ErrNetworkSummary, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return errors.Join(ErrNetworkSummary, err)
	}
	committed = true
	return nil
}

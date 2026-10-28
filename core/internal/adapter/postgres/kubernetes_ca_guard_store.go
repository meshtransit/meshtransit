package postgres

import (
	"context"
	"fmt"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	readKubernetesCAGuardSQL      = `SELECT mesh_ops.read_kubernetes_ca_guard_v1($1::UUID)::TEXT`
	markKubernetesCARestoredSQL   = `SELECT mesh_ops.mark_kubernetes_ca_restored_v1($1::UUID,$2::TEXT,$3::TEXT)::TEXT`
	clearKubernetesCARestoreSQL   = `SELECT mesh_ops.clear_kubernetes_ca_restore_v1($1::UUID,$2::BIGINT,$3::TEXT,$4::TEXT)::TEXT`
	listKubernetesCAIntermediates = `SELECT mesh_ops.list_kubernetes_ca_active_intermediates_v1($1::UUID,$2::INTEGER)::TEXT`

	clusterCAMaximumListed = 256
)

// ErrKubernetesCAIntermediatesActive reports a guard that cannot be cleared
// while an intermediate is still active.
var ErrKubernetesCAIntermediatesActive = fmt.Errorf("postgres Kubernetes CA guard: %w", kubeca.ErrIntermediatesActive)

// ReadGuard reads the installation's restore guard and the marks the worker
// compares (schema 240, a3 §5).
func (store *KubernetesClusterCAStore) ReadGuard(ctx context.Context, installation deployment.ID) (kubeca.Guard,
	error,
) {
	if !store.valid(ctx, installation) {
		return kubeca.Guard{}, ErrInvalidKubernetesClusterCAStore
	}
	encoded, err := store.queryText(ctx, readKubernetesCAGuardSQL, installation.String())
	if err != nil {
		return kubeca.Guard{}, err
	}
	var record struct {
		Suspected       *bool      `json:"suspected"`
		Generation      int64      `json:"generation"`
		MarkedAt        *time.Time `json:"marked_at"`
		CertificateMark int64      `json:"certificate_mark"`
		CAMark          int64      `json:"ca_mark"`
		StartedAt       time.Time  `json:"started_at"`
		FinishedAt      time.Time  `json:"finished_at"`
	}
	if err := decodeStrictJSON(encoded, 1024, &record); err != nil || record.Suspected == nil {
		return kubeca.Guard{}, ErrKubernetesClusterCAStore
	}
	guard := kubeca.Guard{
		Suspected: *record.Suspected, Generation: record.Generation, CertificateMark: record.CertificateMark,
		CAMark: record.CAMark, ReadStarted: record.StartedAt,
		ReadFinished: record.FinishedAt,
	}
	if !guard.Valid() || guard.Suspected && record.MarkedAt == nil {
		return kubeca.Guard{}, ErrKubernetesClusterCAStore
	}
	return guard, nil
}

// MarkRestored stops the installation's CA work until an operator
// reconciles; the first mark of a restore is kept.
func (store *KubernetesClusterCAStore) MarkRestored(ctx context.Context, installation deployment.ID,
	operator kubeca.Operator,
) error {
	if !store.valid(ctx, installation) || operator.IsWorker() || !operator.Valid() {
		return ErrInvalidKubernetesClusterCAStore
	}
	encoded, err := store.queryText(ctx, markKubernetesCARestoredSQL, installation.String(), operator.Name,
		operator.ChangeRef)
	if err != nil {
		return err
	}
	var record struct {
		Outcome    string `json:"outcome"`
		Generation int64  `json:"generation"`
	}
	if err := decodeStrictJSON(encoded, 1024, &record); err != nil || record.Outcome != "suspected" ||
		record.Generation < 1 {
		return ErrKubernetesClusterCAStore
	}
	return nil
}

// ClearRestore resumes the installation's CA work, for the generation the
// operator read; false when another operator cleared or marked it since.
// It refuses while an intermediate is active.
func (store *KubernetesClusterCAStore) ClearRestore(ctx context.Context, installation deployment.ID,
	generation int64, operator kubeca.Operator,
) (bool, error) {
	if !store.valid(ctx, installation) || generation < 1 || operator.IsWorker() || !operator.Valid() {
		return false, ErrInvalidKubernetesClusterCAStore
	}
	encoded, err := store.queryText(ctx, clearKubernetesCARestoreSQL, installation.String(), generation,
		operator.Name, operator.ChangeRef)
	if err != nil {
		return false, err
	}
	var record struct {
		Outcome    string `json:"outcome"`
		Generation *int64 `json:"generation"`
	}
	if err := decodeStrictJSON(encoded, 1024, &record); err != nil {
		return false, ErrKubernetesClusterCAStore
	}
	switch {
	case record.Outcome == "cleared" && record.Generation != nil && *record.Generation > generation:
		return true, nil
	case (record.Outcome == "stale" || record.Outcome == "clear") && record.Generation == nil:
		return false, nil
	case record.Outcome == "intermediates_active" && record.Generation == nil:
		return false, ErrKubernetesCAIntermediatesActive
	}
	return false, ErrKubernetesClusterCAStore
}

// ListActiveIntermediates lists the installation's active intermediates,
// oldest first, at most limit.
func (store *KubernetesClusterCAStore) ListActiveIntermediates(ctx context.Context, installation deployment.ID,
	limit int,
) ([]kubeca.IntermediateRef, error) {
	if !store.valid(ctx, installation) || limit < 1 || limit > clusterCAMaximumListed {
		return nil, ErrInvalidKubernetesClusterCAStore
	}
	encoded, err := store.queryText(ctx, listKubernetesCAIntermediates, installation.String(), limit)
	if err != nil {
		return nil, err
	}
	var record struct {
		Intermediates []struct {
			WorkspaceID string `json:"workspace_id"`
			NetworkID   string `json:"network_id"`
			ClusterID   string `json:"cluster_id"`
			CAID        string `json:"ca_id"`
			Version     int64  `json:"version"`
		} `json:"intermediates"`
	}
	if err := decodeStrictJSON(encoded, 1<<20, &record); err != nil || record.Intermediates == nil ||
		len(record.Intermediates) > limit {
		return nil, ErrKubernetesClusterCAStore
	}
	listed := make([]kubeca.IntermediateRef, 0, len(record.Intermediates))
	for _, item := range record.Intermediates {
		scope, scopeErr := parseClusterCAScope(item.WorkspaceID, item.NetworkID)
		cluster, clusterErr := publicid.Parse(item.ClusterID)
		ca, caErr := publicid.Parse(item.CAID)
		if scopeErr != nil || clusterErr != nil || caErr != nil || item.Version < 1 {
			return nil, ErrKubernetesClusterCAStore
		}
		listed = append(listed, kubeca.IntermediateRef{Scope: scope, Cluster: cluster, CA: ca, Version: item.Version})
	}
	return listed, nil
}

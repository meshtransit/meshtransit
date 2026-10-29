package postgres

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/kubeca/lifecycle"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// Schema 252 (K1d d2a): the worker's queue of people's requests to retire a
// CA. Done is marked inside the change that retires the CA (Change with
// Completes); a refusal in its own short transaction.
const (
	readKubernetesCARetireWorkSQL     = `SELECT mesh_ops.read_kubernetes_ca_retire_work_v1($1::UUID,$2::INTEGER)::TEXT`
	completeKubernetesCARetireSQL     = `SELECT mesh_ops.complete_kubernetes_ca_retire_request_v1($1::UUID,$2::UUID,$3::UUID,$4::UUID)`
	refuseKubernetesCARetireSQL       = `SELECT mesh_ops.refuse_kubernetes_ca_retire_request_v1($1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::TEXT)`
	kubernetesCARetireMaximumRequests = 64
)

// errKubernetesCARetireNotWaiting reports a request another worker ended
// first: the change that would carry it out is not applied.
var errKubernetesCARetireNotWaiting = errors.New("postgres Kubernetes CA retire request no longer waits")

// KubernetesCARetireQueue is the worker's view of the retire requests.
type KubernetesCARetireQueue struct{ store *KubernetesClusterCAStore }

// RetireQueue returns the queue that shares the CA store's pool.
func (store *KubernetesClusterCAStore) RetireQueue() *KubernetesCARetireQueue {
	return &KubernetesCARetireQueue{store: store}
}

// List reads the oldest waiting requests and the database's clock.
func (queue *KubernetesCARetireQueue) List(ctx context.Context, installation deployment.ID,
	limit int) (lifecycle.RetireQueue, error) {
	if queue == nil || !queue.store.valid(ctx, installation) || limit < 1 ||
		limit > kubernetesCARetireMaximumRequests {
		return lifecycle.RetireQueue{}, ErrInvalidKubernetesClusterCAStore
	}
	encoded, err := queue.store.queryText(ctx, readKubernetesCARetireWorkSQL, installation.String(), limit)
	if err != nil {
		return lifecycle.RetireQueue{}, err
	}
	var read struct {
		Now      time.Time `json:"now"`
		Requests []struct {
			WorkspaceID string    `json:"workspace_id"`
			NetworkID   string    `json:"network_id"`
			ClusterID   string    `json:"cluster_id"`
			RequestID   string    `json:"request_id"`
			CAID        string    `json:"ca_id"`
			CAVersion   int64     `json:"ca_version"`
			CAState     string    `json:"ca_state"`
			Reason      string    `json:"reason"`
			ExpiresAt   time.Time `json:"expires_at"`
		} `json:"requests"`
	}
	if err := decodeIdentityCatalogJSON([]byte(encoded), &read); err != nil || read.Now.IsZero() ||
		read.Requests == nil || len(read.Requests) > limit {
		return lifecycle.RetireQueue{}, ErrKubernetesClusterCAStore
	}
	queued := lifecycle.RetireQueue{Now: read.Now.UTC(), Waiting: make([]kubeca.RetireRequest, 0, len(read.Requests))}
	for _, row := range read.Requests {
		scope, err := parseClusterCAScope(row.WorkspaceID, row.NetworkID)
		cluster, clusterErr := publicid.Parse(row.ClusterID)
		id, idErr := publicid.Parse(row.RequestID)
		ca, caErr := publicid.Parse(row.CAID)
		state := kubeca.State(row.CAState)
		reason := kubeca.Reason(row.Reason)
		if err != nil || clusterErr != nil || idErr != nil || caErr != nil || row.CAVersion < 1 ||
			row.ExpiresAt.IsZero() || !knownCAState(state) ||
			reason != kubeca.ReasonAdmin && reason != kubeca.ReasonEmergency && reason != kubeca.ReasonCompromise {
			return lifecycle.RetireQueue{}, ErrKubernetesClusterCAStore
		}
		queued.Waiting = append(queued.Waiting, kubeca.RetireRequest{Scope: scope, Cluster: cluster, ID: id, CA: ca,
			CAVersion: row.CAVersion, CAState: state, Reason: reason, ExpiresAt: row.ExpiresAt.UTC()})
	}
	return queued, nil
}

func knownCAState(state kubeca.State) bool {
	return state == kubeca.StateNext || state == kubeca.StateActive || state == kubeca.StateRetiring ||
		state == kubeca.StateRetired
}

// Refuse ends a waiting request with the worker's refusal; false when it no
// longer waits.
func (queue *KubernetesCARetireQueue) Refuse(ctx context.Context, installation deployment.ID,
	scope network.Scope, request publicid.ID, refusal string) (bool, error) {
	if queue == nil || !queue.store.valid(ctx, installation) || !scope.IsValid() || !request.IsValid() ||
		refusal != kubeca.RetireRefusalExpired && refusal != kubeca.RetireRefusalChanged &&
			refusal != kubeca.RetireRefusalGuard && refusal != kubeca.RetireRefusalGone {
		return false, ErrInvalidKubernetesClusterCAStore
	}
	var refused bool
	err := queue.store.inTransaction(ctx, func(transaction outboxTransaction) (bool, error) {
		if err := transaction.QueryRow(ctx, refuseKubernetesCARetireSQL, installation.String(),
			scope.WorkspaceID().String(), scope.NetworkID().String(), request.String(), refusal).Scan(&refused); err != nil {
			return false, errors.Join(ErrKubernetesClusterCAStore, err)
		}
		return true, nil
	})
	return refused, err
}

// completeRetireRequest marks the request a change carries out done, in the
// change's transaction.
func completeRetireRequest(ctx context.Context, transaction outboxTransaction, installation deployment.ID,
	scope network.Scope, request publicid.ID) error {
	var completed bool
	if err := transaction.QueryRow(ctx, completeKubernetesCARetireSQL, installation.String(),
		scope.WorkspaceID().String(), scope.NetworkID().String(), request.String()).Scan(&completed); err != nil {
		return errors.Join(ErrKubernetesClusterCAStore, err)
	}
	if !completed {
		return errKubernetesCARetireNotWaiting
	}
	return nil
}

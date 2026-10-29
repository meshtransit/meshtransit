package postgres

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// Schema 247 (K1d d1a): pages and single rows of a cluster's join keys and
// replica requests.
const (
	listKubernetesJoinKeysSQL = `SELECT mesh_ops.list_kubernetes_join_keys_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TIMESTAMPTZ,$14::UUID,$15::INTEGER)::TEXT`
	readKubernetesJoinKeySQL = `SELECT mesh_ops.read_kubernetes_join_key_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::UUID)::TEXT`
	listKubernetesReplicaRequestsSQL = `SELECT mesh_ops.list_kubernetes_replica_requests_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TIMESTAMPTZ,$14::UUID,$15::INTEGER)::TEXT`
	readKubernetesReplicaRequestSQL = `SELECT mesh_ops.read_kubernetes_replica_request_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::UUID)::TEXT`
)

// readPage runs one page query and decodes its rows: limit + 1 at most,
// the extra one only telling that more follow.
func (store *KubernetesClusterStore) readPage(ctx context.Context, sql string, query kubecluster.PageQuery,
	rows any) error {
	var afterAt *time.Time
	var afterID *string
	if !query.After.IsZero() {
		at, id := query.After.At.UTC(), query.After.ID.String()
		afterAt, afterID = &at, &id
	}
	return store.transact(ctx, query.Scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, sql, append(sessionQueryArguments(query.Session),
			query.Scope.WorkspaceID().String(), query.Scope.NetworkID().String(), query.ClusterID.String(),
			afterAt, afterID, query.Limit)...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), rows); err != nil {
			return false, kubecluster.ErrInvalid
		}
		return false, nil
	})
}

// ListJoinKeys reads a page of a cluster's join keys.
func (store *KubernetesClusterStore) ListJoinKeys(ctx context.Context,
	query kubecluster.PageQuery) (kubecluster.JoinKeyPage, error) {
	var documents []kubernetesJoinKeyDocument
	if err := store.readPage(ctx, listKubernetesJoinKeysSQL, query, &documents); err != nil {
		return kubecluster.JoinKeyPage{}, err
	}
	if documents == nil || len(documents) > query.Limit+1 {
		return kubecluster.JoinKeyPage{}, kubecluster.ErrInvalid
	}
	page := kubecluster.JoinKeyPage{Keys: make([]kubecluster.JoinKey, 0, min(len(documents), query.Limit))}
	previous := query.After
	for _, document := range documents[:min(len(documents), query.Limit)] {
		key, err := document.key()
		if err != nil {
			return kubecluster.JoinKeyPage{}, err
		}
		at, id := key.CreatedAt(), publicid.ID(key.ID())
		if !beforeCursor(previous, at, id) {
			return kubecluster.JoinKeyPage{}, kubecluster.ErrInvalid
		}
		previous = kubecluster.PageCursor{At: at, ID: id}
		page.Keys = append(page.Keys, key)
	}
	if len(documents) > query.Limit {
		page.Next = previous
	}
	return page, nil
}

// ReadJoinKey reads one of a cluster's join keys.
func (store *KubernetesClusterStore) ReadJoinKey(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID, keyID enrollment.CredentialID) (kubecluster.JoinKey, error) {
	var key kubecluster.JoinKey
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, readKubernetesJoinKeySQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), clusterID.String(),
			keyID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var document kubernetesJoinKeyDocument
		if err := decodeIdentityCatalogJSON([]byte(encoded), &document); err != nil {
			return false, kubecluster.ErrInvalid
		}
		read, err := document.key()
		if err != nil || read.ID() != keyID {
			return false, kubecluster.ErrInvalid
		}
		key = read
		return false, nil
	})
	return key, err
}

// ListReplicaRequests reads a page of a cluster's replica requests.
func (store *KubernetesClusterStore) ListReplicaRequests(ctx context.Context,
	query kubecluster.PageQuery) (kubecluster.RequestPage, error) {
	var documents []kubernetesReplicaRequestDocument
	if err := store.readPage(ctx, listKubernetesReplicaRequestsSQL, query, &documents); err != nil {
		return kubecluster.RequestPage{}, err
	}
	if documents == nil || len(documents) > query.Limit+1 {
		return kubecluster.RequestPage{}, kubecluster.ErrInvalid
	}
	page := kubecluster.RequestPage{
		Requests: make([]kubecluster.ReplicaRequestView, 0, min(len(documents), query.Limit)),
	}
	previous := query.After
	for _, document := range documents[:min(len(documents), query.Limit)] {
		view, err := document.view()
		if err != nil {
			return kubecluster.RequestPage{}, err
		}
		at, id := view.Lifecycle().CreatedAt(), publicid.ID(view.ID())
		if view.ClusterID() != query.ClusterID || !beforeCursor(previous, at, id) {
			return kubecluster.RequestPage{}, kubecluster.ErrInvalid
		}
		previous = kubecluster.PageCursor{At: at, ID: id}
		page.Requests = append(page.Requests, view)
	}
	if len(documents) > query.Limit {
		page.Next = previous
	}
	return page, nil
}

// ReadReplicaRequest reads one of a cluster's replica requests.
func (store *KubernetesClusterStore) ReadReplicaRequest(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID,
	requestID kubecluster.RequestID) (kubecluster.ReplicaRequestView, error) {
	var view kubecluster.ReplicaRequestView
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, readKubernetesReplicaRequestSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), clusterID.String(),
			requestID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var document kubernetesReplicaRequestDocument
		if err := decodeIdentityCatalogJSON([]byte(encoded), &document); err != nil {
			return false, kubecluster.ErrInvalid
		}
		read, err := document.view()
		if err != nil || read.ID() != requestID || read.ClusterID() != clusterID {
			return false, kubecluster.ErrInvalid
		}
		view = read
		return false, nil
	})
	return view, err
}

// beforeCursor reports a row strictly older than cursor in the page order
// (time, then ID, both descending); every row is before the zero cursor.
func beforeCursor(cursor kubecluster.PageCursor, at time.Time, id publicid.ID) bool {
	if cursor.IsZero() {
		return true
	}
	if !at.Equal(cursor.At) {
		return at.Before(cursor.At)
	}
	return compareIDs(id, cursor.ID) < 0
}

func compareIDs(left, right publicid.ID) int {
	for index := range left {
		switch {
		case left[index] < right[index]:
			return -1
		case left[index] > right[index]:
			return 1
		}
	}
	return 0
}

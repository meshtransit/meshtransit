package postgres

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
)

// Schema 255 (K1d d4a): recent grants of the right to approve replicas.
const readKubernetesApproverAdditionsSQL = `SELECT mesh_ops.read_kubernetes_cluster_approver_additions_v1(` +
	sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID)::TEXT`

// ReadApproverAdditions reads when someone was last given the right to
// approve the cluster's replicas within a day.
func (store *KubernetesClusterStore) ReadApproverAdditions(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID) (kubecluster.ApproverAdditions, error) {
	var additions kubecluster.ApproverAdditions
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, readKubernetesApproverAdditionsSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), clusterID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var document struct {
			ClusterID string     `json:"cluster_id"`
			LatestAt  *time.Time `json:"latest_at"`
			Count     int        `json:"count"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &document); err != nil ||
			document.ClusterID != clusterID.String() {
			return false, kubecluster.ErrInvalid
		}
		additions = kubecluster.ApproverAdditions{Count: document.Count}
		if document.LatestAt != nil {
			additions.LatestAt = document.LatestAt.UTC()
		}
		if !additions.Valid() {
			return false, kubecluster.ErrInvalid
		}
		return false, nil
	})
	return additions, err
}

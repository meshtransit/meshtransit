package postgres

import (
	"context"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

const readKubernetesExplainReplicaSQL = `SELECT mesh_ops.read_kubernetes_cluster_explain_replica_v1(` +
	sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID)::TEXT`

// ReadExplainReplica reads the active replica with the lowest ordinal of a
// cluster (K1d d4c, schema 256); ErrNoActiveReplica when none is active.
func (store *KubernetesClusterStore) ReadExplainReplica(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID) (node.ID, error) {
	var replica node.ID
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, readKubernetesExplainReplicaSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), clusterID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var document struct {
			ClusterID string  `json:"cluster_id"`
			DeviceID  *string `json:"device_id"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &document); err != nil ||
			document.ClusterID != clusterID.String() {
			return false, kubecluster.ErrInvalid
		}
		if document.DeviceID == nil {
			return false, kubecluster.ErrNoActiveReplica
		}
		parsed, err := node.ParseID(*document.DeviceID)
		if err != nil {
			return false, kubecluster.ErrInvalid
		}
		replica = parsed
		return false, nil
	})
	return replica, err
}

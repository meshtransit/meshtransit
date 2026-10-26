package mapsession

import (
	"context"
	"errors"
	"fmt"

	"meshtransit.net/core/internal/domain/kubecluster"
)

// The gateway replicas of the installed scope and their clusters (schema
// 231), read once this role may run the reader: a map names a cluster, not
// its replicas (K1a2b).
const (
	kubernetesGatewaysGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.load_map_network_kubernetes_gateways_v1()'), 'EXECUTE'), FALSE)`
	loadKubernetesGatewaysSQL = `SELECT numeric_node_id, cluster_name
FROM mesh_ops.load_map_network_kubernetes_gateways_v1()`

	// maximumMapKubernetesGateways bounds one Network's live replicas.
	maximumMapKubernetesGateways = kubecluster.MaximumClustersPerNetwork * kubecluster.MaximumReplicasPerCluster
)

// kubernetesGateways is the cluster of each gateway replica by numeric node
// ID. A replica's cluster and a cluster's name never change, so a cached
// candidate keeps its cluster until the Device changes.
type kubernetesGateways map[int64]kubecluster.Name

// readKubernetesGateways reads the scope's replicas; granted is false, and
// every Device is standard, while the database lacks schema 231. Schemas
// only move forward, so once granted the reader is not probed again.
func (store *Store) readKubernetesGateways(ctx context.Context, transaction databaseTransaction) (
	gateways kubernetesGateways, granted bool, resultErr error) {
	if !store.gatewaysGranted.Load() {
		granted, err := functionGranted(ctx, transaction, kubernetesGatewaysGrantedSQL)
		if err != nil {
			return nil, false, errors.Join(ErrLoadSnapshot, fmt.Errorf("check gateway reader: %w", err))
		}
		if !granted {
			return nil, false, nil
		}
		store.gatewaysGranted.Store(true)
	}
	rows, err := transaction.Query(ctx, loadKubernetesGatewaysSQL)
	if err != nil || rows == nil {
		return nil, false, errors.Join(ErrLoadSnapshot, fmt.Errorf("read gateways: %w", nonNil(err)))
	}
	defer rows.Close()
	gateways = kubernetesGateways{}
	for rows.Next() {
		if len(gateways) == maximumMapKubernetesGateways {
			return nil, false, ErrSnapshotEvidence
		}
		var numericNodeID int64
		var name string
		if err := rows.Scan(&numericNodeID, &name); err != nil {
			return nil, false, errors.Join(ErrLoadSnapshot, fmt.Errorf("scan gateway: %w", err))
		}
		cluster, err := kubecluster.ParseName(name)
		if _, duplicate := gateways[numericNodeID]; err != nil || numericNodeID <= 0 || duplicate {
			return nil, false, ErrSnapshotEvidence
		}
		gateways[numericNodeID] = cluster
	}
	if err := rows.Err(); err != nil {
		return nil, false, errors.Join(ErrLoadSnapshot, fmt.Errorf("iterate gateways: %w", err))
	}
	return gateways, true, nil
}

// mark sets the cluster of a replica's record.
func (gateways kubernetesGateways) mark(record *peerCandidateRecord) {
	record.kubernetesCluster = gateways[record.numericNodeID]
}

package postgres

import (
	"context"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

// Schema 253 (K1d d2b): an approver suspends or resumes a replica's pod
// token ratchet; the handshakes read the suspension.
const (
	suspendKubernetesGatewayRatchetSQL = `SELECT mesh_ops.suspend_kubernetes_gateway_token_ratchet_v1(` +
		sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::UUID,$14::INTEGER,$15::UUID)::TEXT`
	resumeKubernetesGatewayRatchetSQL = `SELECT mesh_ops.resume_kubernetes_gateway_token_ratchet_v1(` +
		sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::UUID,$14::UUID)::TEXT`
	gatewayRatchetSuspendedAction = "kubernetes_gateway.token_ratchet_suspended"
	gatewayRatchetResumedAction   = "kubernetes_gateway.token_ratchet_resumed"
)

// ChangeTokenRatchet suspends or resumes a replica's ratchet and records
// who did it and why on the Network's stream.
func (store *KubernetesClusterStore) ChangeTokenRatchet(ctx context.Context,
	change kubecluster.RatchetChange) (kubecluster.RatchetChangeResult, error) {
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.RatchetChangeResult{}, kubecluster.ErrUnavailable
	}
	scope := change.Scope
	arguments := append(sessionQueryArguments(change.Session), scope.WorkspaceID().String(),
		scope.NetworkID().String(), change.ClusterID.String(), change.DeviceID.String())
	statement := resumeKubernetesGatewayRatchetSQL
	if change.Suspends() {
		statement = suspendKubernetesGatewayRatchetSQL
		arguments = append(arguments, int64(change.Duration/time.Second))
	}
	arguments = append(arguments, changeID.String())
	var result kubecluster.RatchetChangeResult
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, statement, arguments...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record struct {
			NetworkID       string            `json:"network_id"`
			NetworkRevision *int64            `json:"network_revision"`
			ClusterID       string            `json:"cluster_id"`
			DeviceID        string            `json:"device_id"`
			Changed         bool              `json:"changed"`
			SuspendedUntil  *time.Time        `json:"suspended_until"`
			Authority       *catalogAuthority `json:"authority"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil ||
			record.NetworkID != scope.NetworkID().String() || record.ClusterID != change.ClusterID.String() ||
			record.DeviceID != change.DeviceID.String() || (record.SuspendedUntil != nil) != change.Suspends() ||
			change.Suspends() && !record.Changed {
			return false, kubecluster.ErrInvalid
		}
		result = kubecluster.RatchetChangeResult{Changed: record.Changed}
		if record.SuspendedUntil != nil {
			result.SuspendedUntil = record.SuspendedUntil.UTC()
		}
		if !record.Changed {
			return false, nil
		}
		if record.NetworkRevision == nil || *record.NetworkRevision < 1 || record.Authority == nil {
			return false, kubecluster.ErrInvalid
		}
		return true, store.appendRatchetChangeEvent(ctx, tx, change, changeID, *record.NetworkRevision,
			*record.Authority, result)
	})
	return result, err
}

func (store *KubernetesClusterStore) appendRatchetChangeEvent(ctx context.Context, tx accountSessionTransaction,
	change kubecluster.RatchetChange, changeID publicid.ID, networkRevision int64, authority catalogAuthority,
	result kubecluster.RatchetChangeResult) error {
	type audited struct {
		NetworkID      string  `json:"network_id"`
		ClusterID      string  `json:"cluster_id"`
		DeviceID       string  `json:"device_id"`
		SuspendedUntil *string `json:"suspended_until"`
		Reason         string  `json:"reason"`
		ChangeRef      string  `json:"change_ref"`
	}
	action := gatewayRatchetResumedAction
	var until *string
	if change.Suspends() {
		action = gatewayRatchetSuspendedAction
		text := result.SuspendedUntil.Format(time.RFC3339Nano)
		until = &text
	}
	networkID, clusterID, deviceID := change.Scope.NetworkID().String(), change.ClusterID.String(),
		change.DeviceID.String()
	after := audited{networkID, clusterID, deviceID, until, change.Reason, change.ChangeRef}
	afterHash, err := kubernetesSemanticHash(after)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	event := catalogEvent{
		session: change.Session, correlationID: change.CorrelationID, changeID: changeID,
		aggregateKind: "kubernetes_gateway_ratchet_change", aggregateID: changeID,
		version: 1, networkVersion: networkRevision, action: action,
		permission: "kubernetes_cluster.approve", after: afterHash, outboxClass: action,
		outbox: struct {
			NetworkID      string  `json:"network_id"`
			ClusterID      string  `json:"cluster_id"`
			DeviceID       string  `json:"device_id"`
			SuspendedUntil *string `json:"suspended_until"`
		}{networkID, clusterID, deviceID, until},
	}
	event.payload = struct {
		NetworkID string           `json:"network_id"`
		SessionID string           `json:"session_id"`
		ClusterID string           `json:"cluster_id"`
		After     audited          `json:"after"`
		Authority catalogAuthority `json:"authority"`
	}{networkID, change.Session.ID().String(), clusterID, after, authority}
	return appendNetworkMemberEvent(ctx, tx, event)
}

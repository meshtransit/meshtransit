package postgres

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// Install-token approval and trust actions (V1-12 step 1c, schema 309).

const (
	preapproveKubernetesReplicaRequestSQL = `SELECT mesh_ops.preapprove_kubernetes_replica_request_v1(
 $1::UUID,$2::UUID,$3::TEXT,$4::TIMESTAMPTZ,$5::UUID)::TEXT`
	confirmKubernetesClusterTrustSQL = `SELECT mesh_ops.confirm_kubernetes_cluster_trust_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::BYTEA,$14::BIGINT,$15::UUID)::TEXT`
	chooseKubernetesClusterTrustSQL = `SELECT mesh_ops.choose_kubernetes_cluster_trust_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::BYTEA,$14::BIGINT,$15::UUID)::TEXT`
	resetKubernetesClusterTrustSQL = `SELECT mesh_ops.reset_kubernetes_cluster_trust_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TEXT,$14::BIGINT,$15::UUID)::TEXT`
)

var (
	_ kubecluster.PreapprovalStore = (*KubernetesClusterStore)(nil)
	_ kubecluster.TrustStore       = (*KubernetesClusterStore)(nil)
)

// kubernetesTrustDocument is a signing trust as schema 309 returns it.
type kubernetesTrustDocument struct {
	TrustID         string     `json:"trust_id"`
	Version         int64      `json:"version"`
	Source          string     `json:"source"`
	State           string     `json:"state"`
	Digest          *string    `json:"digest"`
	Issuer          string     `json:"issuer"`
	Namespace       string     `json:"namespace"`
	ServiceAccount  string     `json:"service_account"`
	StatefulSet     string     `json:"statefulset"`
	KeyThumbprints  []string   `json:"key_thumbprints"`
	ContestedDigest *string    `json:"contested_digest"`
	ContestedAt     *time.Time `json:"contested_at"`
	ConfirmedAt     *time.Time `json:"confirmed_at"`
}

func (document *kubernetesTrustDocument) semanticHash(networkID, clusterID string) ([32]byte, error) {
	if document == nil {
		return kubernetesSemanticHash(struct {
			NetworkID string `json:"network_id"`
			ClusterID string `json:"cluster_id"`
			Trust     *bool  `json:"trust"`
		}{networkID, clusterID, nil})
	}
	return kubernetesSemanticHash(struct {
		NetworkID       string   `json:"network_id"`
		ClusterID       string   `json:"cluster_id"`
		TrustID         string   `json:"trust_id"`
		Source          string   `json:"source"`
		State           string   `json:"state"`
		Digest          *string  `json:"digest"`
		Issuer          string   `json:"issuer"`
		Namespace       string   `json:"namespace"`
		ServiceAccount  string   `json:"service_account"`
		StatefulSet     string   `json:"statefulset"`
		KeyThumbprints  []string `json:"key_thumbprints"`
		ContestedDigest *string  `json:"contested_digest"`
	}{networkID, clusterID, document.TrustID, document.Source, document.State, document.Digest, document.Issuer,
		document.Namespace, document.ServiceAccount, document.StatefulSet, document.KeyThumbprints,
		document.ContestedDigest})
}

type kubernetesPreapprovalRecord struct {
	Outcome          string                            `json:"outcome"`
	Reason           string                            `json:"reason"`
	ApproverID       string                            `json:"approver_principal_id"`
	ClusterID        string                            `json:"cluster_id"`
	Cluster          *kubernetesClusterDocument        `json:"cluster"`
	NetworkID        string                            `json:"network_id"`
	NetworkRevision  int64                             `json:"network_revision"`
	TrustSet         bool                              `json:"trust_set"`
	Trust            *kubernetesTrustDocument          `json:"trust"`
	PodOrdinal       *int                              `json:"pod_ordinal"`
	NewUse           bool                              `json:"new_use"`
	SuspendedDevices []string                          `json:"suspended_devices"`
	RevokedTokens    int64                             `json:"revoked_tokens"`
	Before           *kubernetesReplicaRequestDocument `json:"before"`
	Request          kubernetesReplicaRequestDocument  `json:"request"`
}

// Preapprove approves, in the name of the token's maker, a request opened
// with an install token, or contests or refuses it (schema 309), and
// records what it did. An ordinary key's request is left waiting.
func (store *KubernetesClusterStore) Preapprove(ctx context.Context, preapproval kubecluster.Preapproval) (
	kubecluster.PreapprovalResult, error) {
	if !preapproval.KeyID.IsValid() || !preapproval.RequestID.IsValid() ||
		!preapproval.Pod.IsValidAt(time.Now().UTC()) {
		return kubecluster.PreapprovalResult{}, kubecluster.ErrInvalid
	}
	scope, deploymentID, _, err := store.joinScope(ctx, preapproval.KeyID)
	if err != nil {
		return kubecluster.PreapprovalResult{}, err
	}
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.PreapprovalResult{}, kubecluster.ErrUnavailable
	}
	var result kubecluster.PreapprovalResult
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, preapproveKubernetesReplicaRequestSQL, preapproval.RequestID.String(),
			preapproval.Pod.PodUID, preapproval.Pod.JTI, preapproval.Pod.ExpiresAt.UTC(),
			changeID.String()).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record kubernetesPreapprovalRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil {
			return false, kubecluster.ErrInvalid
		}
		decoded, err := record.result(preapproval, scope)
		if err != nil {
			return false, err
		}
		result = decoded
		if decoded.Outcome == kubecluster.PreapprovalNotPreapproved {
			return false, nil
		}
		return true, store.appendPreapprovalEvents(ctx, tx, scope, deploymentID, changeID, record)
	})
	if err != nil {
		return kubecluster.PreapprovalResult{}, err
	}
	return result, nil
}

func (record kubernetesPreapprovalRecord) result(preapproval kubecluster.Preapproval, scope network.Scope) (
	kubecluster.PreapprovalResult, error) {
	view, err := record.Request.view()
	if err != nil || view.ID() != preapproval.RequestID {
		return kubecluster.PreapprovalResult{}, kubecluster.ErrInvalid
	}
	result := kubecluster.PreapprovalResult{Outcome: kubecluster.PreapprovalOutcome(record.Outcome), Request: view}
	if result.Outcome == kubecluster.PreapprovalNotPreapproved {
		return result, nil
	}
	if record.NetworkID != scope.NetworkID().String() || record.NetworkRevision <= 0 || record.Before == nil {
		return kubecluster.PreapprovalResult{}, kubecluster.ErrInvalid
	}
	if _, err := publicid.Parse(record.ApproverID); err != nil {
		return kubecluster.PreapprovalResult{}, kubecluster.ErrInvalid
	}
	switch result.Outcome {
	case kubecluster.PreapprovalApproved:
		if view.Lifecycle().State() != kubecluster.RequestApproved || record.Trust == nil ||
			record.PodOrdinal == nil || (record.TrustSet && record.Trust.State != "unconfirmed") {
			return kubecluster.PreapprovalResult{}, kubecluster.ErrInvalid
		}
		result.TrustPinned = record.TrustSet
	case kubecluster.PreapprovalContested:
		if record.Trust == nil || record.Trust.State != "contested" || record.Cluster == nil ||
			record.RevokedTokens < 0 {
			return kubecluster.PreapprovalResult{}, kubecluster.ErrInvalid
		}
		devices, err := parsePublicIDs(record.SuspendedDevices)
		if err != nil {
			return kubecluster.PreapprovalResult{}, err
		}
		result.SuspendedDevices, result.RevokedTokens = devices, int(record.RevokedTokens)
	case kubecluster.PreapprovalRefused:
		if !kubecluster.KnownRefusal(record.Reason) {
			return kubecluster.PreapprovalResult{}, kubecluster.ErrInvalid
		}
		result.Reason = record.Reason
	default:
		return kubecluster.PreapprovalResult{}, kubecluster.ErrInvalid
	}
	return result, nil
}

func parsePublicIDs(values []string) ([]publicid.ID, error) {
	ids := make([]publicid.ID, 0, len(values))
	for _, value := range values {
		id, err := publicid.Parse(value)
		if err != nil {
			return nil, kubecluster.ErrInvalid
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// appendPreapprovalEvents records the approval (or refusal) of the
// request, with the token's maker as actor, and what it did to the
// cluster's trust: pinned or contested.
func (store *KubernetesClusterStore) appendPreapprovalEvents(ctx context.Context, tx accountSessionTransaction,
	scope network.Scope, deploymentID deployment.ID, changeID publicid.ID, record kubernetesPreapprovalRecord) error {
	actor, err := publicid.Parse(record.ApproverID)
	requestID, requestErr := publicid.Parse(record.Request.RequestID)
	clusterID, clusterErr := publicid.Parse(record.ClusterID)
	if err != nil || requestErr != nil || clusterErr != nil {
		return kubecluster.ErrInvalid
	}
	networkID := scope.NetworkID().String()
	requestHash := func(document kubernetesReplicaRequestDocument) ([32]byte, error) {
		return kubernetesSemanticHash(struct {
			NetworkID  string  `json:"network_id"`
			RequestID  string  `json:"request_id"`
			State      string  `json:"state"`
			ApprovedBy *string `json:"approved_by_principal_id"`
			Ordinal    *int    `json:"reserved_ordinal"`
		}{networkID, document.RequestID, document.State, document.ApprovedBy, document.ReservedOrdinal})
	}
	before, err := requestHash(*record.Before)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	after, err := requestHash(record.Request)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	action := "kubernetes_replica_request.preapproved"
	if record.Outcome != string(kubecluster.PreapprovalApproved) {
		action = "kubernetes_replica_request.preapproval_refused"
	}
	reason := record.Reason
	if record.Outcome == string(kubecluster.PreapprovalContested) {
		reason = kubecluster.RefusedTrustContested
	}
	var digest *string
	if record.Trust != nil {
		digest = record.Trust.Digest
	}
	events := []catalogEvent{{
		correlationID: changeID, changeID: changeID, aggregateKind: "kubernetes_replica_request",
		aggregateID: requestID, version: record.Request.Version, networkVersion: record.NetworkRevision,
		action: action, permission: "kubernetes_cluster.approve", before: &before, after: after,
		actor: actor, deployment: deploymentID.String(),
		payload: struct {
			NetworkID        string  `json:"network_id"`
			ClusterID        string  `json:"cluster_id"`
			RequestID        string  `json:"request_id"`
			KeyID            string  `json:"key_id"`
			ApproverID       string  `json:"approver_principal_id"`
			State            string  `json:"state"`
			Reason           string  `json:"reason,omitempty"`
			PodOrdinal       *int    `json:"pod_ordinal,omitempty"`
			NewUse           bool    `json:"new_use"`
			ReservedHostname *string `json:"reserved_hostname,omitempty"`
			TrustDigest      *string `json:"trust_digest,omitempty"`
		}{networkID, record.ClusterID, record.Request.RequestID, record.Request.KeyID, record.ApproverID,
			record.Request.State, reason, record.PodOrdinal, record.NewUse, record.Request.ReservedHostname, digest},
		outboxClass: action,
		outbox: struct {
			NetworkID string `json:"network_id"`
			ClusterID string `json:"cluster_id"`
			RequestID string `json:"request_id"`
			Version   int64  `json:"version"`
		}{networkID, record.ClusterID, record.Request.RequestID, record.Request.Version},
	}}
	trustAction := ""
	switch {
	case record.Outcome == string(kubecluster.PreapprovalApproved) && record.TrustSet:
		trustAction = "kubernetes_cluster.trust_pinned"
	case record.Outcome == string(kubecluster.PreapprovalContested):
		trustAction = "kubernetes_cluster.trust_contested"
	}
	if trustAction != "" {
		trustAfter, err := record.Trust.semanticHash(networkID, record.ClusterID)
		if err != nil {
			return kubecluster.ErrInvalid
		}
		version := record.Trust.Version
		if record.Cluster != nil {
			version = record.Cluster.Version
		}
		events = append(events, catalogEvent{
			correlationID: changeID, changeID: changeID, aggregateKind: "kubernetes_cluster",
			aggregateID: clusterID, version: version, networkVersion: record.NetworkRevision,
			action: trustAction, permission: "kubernetes_cluster.approve", after: trustAfter,
			actor: actor, deployment: deploymentID.String(),
			payload: struct {
				NetworkID        string                   `json:"network_id"`
				ClusterID        string                   `json:"cluster_id"`
				RequestID        string                   `json:"request_id"`
				Trust            *kubernetesTrustDocument `json:"trust"`
				SuspendedDevices []string                 `json:"suspended_devices"`
				RevokedTokens    int64                    `json:"revoked_tokens"`
			}{networkID, record.ClusterID, record.Request.RequestID, record.Trust, record.SuspendedDevices,
				record.RevokedTokens},
			outboxClass: trustAction,
			outbox: struct {
				NetworkID string `json:"network_id"`
				ClusterID string `json:"cluster_id"`
				Version   int64  `json:"version"`
			}{networkID, record.ClusterID, version},
		})
	}
	for _, event := range events {
		if err := appendNetworkMemberEvent(ctx, tx, event); err != nil {
			return errors.Join(kubecluster.ErrUnavailable, err)
		}
	}
	return nil
}

type kubernetesTrustActionRecord struct {
	NetworkID        string                    `json:"network_id"`
	NetworkRevision  int64                     `json:"network_revision"`
	TrustMode        string                    `json:"trust_mode"`
	Changed          bool                      `json:"changed"`
	BeforeCluster    kubernetesClusterDocument `json:"before_cluster"`
	Cluster          kubernetesClusterDocument `json:"cluster"`
	Before           *kubernetesTrustDocument  `json:"before"`
	Trust            *kubernetesTrustDocument  `json:"trust"`
	Reason           string                    `json:"reason"`
	ResumedDevices   []string                  `json:"resumed_devices"`
	RevokedDevices   []string                  `json:"revoked_devices"`
	SuspendedDevices []string                  `json:"suspended_devices"`
	RevokedTokens    int64                     `json:"revoked_tokens"`
	Authority        catalogAuthority          `json:"authority"`
}

// ConfirmTrust authorizes kubernetes_cluster.approve and .manage and
// confirms the unconfirmed install-token trust with the digest the
// administrator compared (kubernetes_cluster.trust_confirmed).
func (store *KubernetesClusterStore) ConfirmTrust(ctx context.Context, decision kubecluster.TrustDecision) (
	kubecluster.TrustDecisionResult, error) {
	return store.trustAction(ctx, decision.Session, decision.Scope, decision.ClusterID, decision.CorrelationID,
		"kubernetes_cluster.trust_confirmed", confirmKubernetesClusterTrustSQL, decision.Digest[:], decision.Version)
}

// ChooseTrust authorizes approve and manage and makes the contest's side
// with the given digest the confirmed trust; the gateways approved under it
// resume, the others are revoked (kubernetes_cluster.trust_chosen).
func (store *KubernetesClusterStore) ChooseTrust(ctx context.Context, decision kubecluster.TrustDecision) (
	kubecluster.TrustDecisionResult, error) {
	return store.trustAction(ctx, decision.Session, decision.Scope, decision.ClusterID, decision.CorrelationID,
		"kubernetes_cluster.trust_chosen", chooseKubernetesClusterTrustSQL, decision.Digest[:], decision.Version)
}

// ResetTrust authorizes approve and manage, removes the install-token
// trust, suspends the cluster's gateways, revokes its install tokens and
// returns it to code mode (kubernetes_cluster.trust_reset).
func (store *KubernetesClusterStore) ResetTrust(ctx context.Context, reset kubecluster.TrustReset) (
	kubecluster.TrustDecisionResult, error) {
	return store.trustAction(ctx, reset.Session, reset.Scope, reset.ClusterID, reset.CorrelationID,
		"kubernetes_cluster.trust_reset", resetKubernetesClusterTrustSQL, reset.Reason, reset.Version)
}

func (store *KubernetesClusterStore) trustAction(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID, correlationID publicid.ID, action, query string, argument any,
	version int64) (kubecluster.TrustDecisionResult, error) {
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.TrustDecisionResult{}, kubecluster.ErrUnavailable
	}
	var result kubecluster.TrustDecisionResult
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, query, append(sessionQueryArguments(session), scope.WorkspaceID().String(),
			scope.NetworkID().String(), clusterID.String(), argument, version,
			changeID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record kubernetesTrustActionRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil ||
			record.NetworkID != scope.NetworkID().String() || record.NetworkRevision <= 0 ||
			record.Cluster.ClusterID != clusterID.String() || record.RevokedTokens < 0 {
			return false, kubecluster.ErrInvalid
		}
		cluster, err := record.Cluster.cluster()
		if err != nil {
			return false, err
		}
		resumed, err := parsePublicIDs(record.ResumedDevices)
		if err != nil {
			return false, err
		}
		revoked, err := parsePublicIDs(record.RevokedDevices)
		if err != nil {
			return false, err
		}
		suspended, err := parsePublicIDs(record.SuspendedDevices)
		if err != nil {
			return false, err
		}
		result = kubecluster.TrustDecisionResult{Cluster: cluster, Changed: record.Changed, ResumedDevices: resumed,
			RevokedDevices: revoked, SuspendedDevices: suspended, RevokedTokens: int(record.RevokedTokens)}
		if !record.Changed {
			return false, nil
		}
		return true, store.appendTrustActionEvent(ctx, tx, session, correlationID, changeID, action, record)
	})
	return result, err
}

func (store *KubernetesClusterStore) appendTrustActionEvent(ctx context.Context, tx accountSessionTransaction,
	session accountsession.Session, correlationID, changeID publicid.ID, action string,
	record kubernetesTrustActionRecord) error {
	clusterID, err := kubecluster.ParseID(record.Cluster.ClusterID)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	before, err := record.Before.semanticHash(record.NetworkID, record.Cluster.ClusterID)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	after, err := record.Trust.semanticHash(record.NetworkID, record.Cluster.ClusterID)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	event := catalogEvent{
		session: session, correlationID: correlationID, changeID: changeID,
		aggregateKind: "kubernetes_cluster", aggregateID: publicid.ID(clusterID),
		version: record.Cluster.Version, networkVersion: record.NetworkRevision,
		action: action, permission: "kubernetes_cluster.manage", before: &before, after: after,
		payload: struct {
			NetworkID        string                   `json:"network_id"`
			SessionID        string                   `json:"session_id"`
			ClusterID        string                   `json:"cluster_id"`
			TrustMode        string                   `json:"trust_mode"`
			Before           *kubernetesTrustDocument `json:"before"`
			Trust            *kubernetesTrustDocument `json:"trust"`
			Reason           string                   `json:"reason,omitempty"`
			ResumedDevices   []string                 `json:"resumed_devices,omitempty"`
			RevokedDevices   []string                 `json:"revoked_devices,omitempty"`
			SuspendedDevices []string                 `json:"suspended_devices,omitempty"`
			RevokedTokens    int64                    `json:"revoked_tokens"`
			Authority        catalogAuthority         `json:"authority"`
		}{record.NetworkID, session.ID().String(), record.Cluster.ClusterID, record.TrustMode, record.Before,
			record.Trust, record.Reason, record.ResumedDevices, record.RevokedDevices, record.SuspendedDevices,
			record.RevokedTokens, record.Authority},
		outboxClass: action,
		outbox: struct {
			NetworkID string `json:"network_id"`
			ClusterID string `json:"cluster_id"`
			Version   int64  `json:"version"`
		}{record.NetworkID, record.Cluster.ClusterID, record.Cluster.Version},
	}
	if err := appendNetworkMemberEvent(ctx, tx, event); err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	return nil
}

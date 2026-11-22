package postgres

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

// Install tokens (V1-12 step 1b, schema 307).

const (
	setKubernetesClusterTrustModeSQL = `SELECT mesh_ops.set_kubernetes_cluster_trust_mode_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TEXT,$14::BIGINT,$15::UUID)::TEXT`
	issueKubernetesInstallTokenSQL = `SELECT mesh_ops.issue_kubernetes_preapproved_join_key_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::UUID,$14::UUID,$15::TEXT,$16::BYTEA,$17::BYTEA,$18::BIGINT,$19::INTEGER,$20::UUID)::TEXT`
)

type kubernetesTrustModeRecord struct {
	NetworkID       string                     `json:"network_id"`
	NetworkRevision int64                      `json:"network_revision"`
	Changed         bool                       `json:"changed"`
	RevokedTokens   int64                      `json:"revoked_tokens"`
	TrustMode       string                     `json:"trust_mode"`
	BeforeTrustMode string                     `json:"before_trust_mode"`
	Before          *kubernetesClusterDocument `json:"before"`
	Cluster         kubernetesClusterDocument  `json:"cluster"`
	Authority       catalogAuthority           `json:"authority"`
}

type kubernetesInstallTokenRecord struct {
	kubernetesJoinKeyRecord
	Preapproval *struct {
		Replicas int `json:"replicas"`
	} `json:"preapproval"`
}

// SetTrustMode authorizes kubernetes_cluster.manage and .approve, sets the
// mode of a cluster that trusts no keys yet and records
// kubernetes_cluster.trust_mode_changed.
func (store *KubernetesClusterStore) SetTrustMode(ctx context.Context, change kubecluster.TrustModeChange) (
	kubecluster.TrustModeResult, error) {
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.TrustModeResult{}, kubecluster.ErrUnavailable
	}
	scope := change.Scope
	var result kubecluster.TrustModeResult
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, setKubernetesClusterTrustModeSQL, append(sessionQueryArguments(change.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), change.ClusterID.String(), string(change.Mode),
			change.Version, changeID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record kubernetesTrustModeRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil ||
			record.NetworkID != scope.NetworkID().String() || record.NetworkRevision <= 0 ||
			record.Cluster.ClusterID != change.ClusterID.String() || kubecluster.TrustMode(record.TrustMode) != change.Mode ||
			record.RevokedTokens < 0 || record.Changed != (record.Before != nil) {
			return false, kubecluster.ErrInvalid
		}
		cluster, err := record.Cluster.cluster()
		if err != nil {
			return false, err
		}
		result = kubecluster.TrustModeResult{Cluster: cluster, Mode: change.Mode, Changed: record.Changed,
			RevokedTokens: int(record.RevokedTokens)}
		if !record.Changed {
			return false, nil
		}
		return true, store.appendTrustModeEvent(ctx, tx, change.Session, change.CorrelationID, changeID, record)
	})
	return result, err
}

func (store *KubernetesClusterStore) appendTrustModeEvent(ctx context.Context, tx accountSessionTransaction,
	session accountsession.Session, correlationID, changeID publicid.ID, record kubernetesTrustModeRecord) error {
	clusterID, err := kubecluster.ParseID(record.Cluster.ClusterID)
	if err != nil || record.Before == nil {
		return kubecluster.ErrInvalid
	}
	hash := func(mode string) ([32]byte, error) {
		return kubernetesSemanticHash(struct {
			NetworkID string `json:"network_id"`
			ClusterID string `json:"cluster_id"`
			TrustMode string `json:"trust_mode"`
		}{record.NetworkID, record.Cluster.ClusterID, mode})
	}
	before, err := hash(record.BeforeTrustMode)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	after, err := hash(record.TrustMode)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	event := catalogEvent{
		session: session, correlationID: correlationID, changeID: changeID,
		aggregateKind: "kubernetes_cluster", aggregateID: publicid.ID(clusterID),
		version: record.Cluster.Version, networkVersion: record.NetworkRevision,
		action: "kubernetes_cluster.trust_mode_changed", permission: "kubernetes_cluster.manage",
		before: &before, after: after,
		payload: struct {
			NetworkID     string           `json:"network_id"`
			SessionID     string           `json:"session_id"`
			ClusterID     string           `json:"cluster_id"`
			Before        string           `json:"before_trust_mode"`
			TrustMode     string           `json:"trust_mode"`
			RevokedTokens int64            `json:"revoked_tokens"`
			Authority     catalogAuthority `json:"authority"`
		}{record.NetworkID, session.ID().String(), record.Cluster.ClusterID, record.BeforeTrustMode,
			record.TrustMode, record.RevokedTokens, record.Authority},
		outboxClass: "kubernetes_cluster.trust_mode_changed",
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

// IssueInstallToken authorizes kubernetes_cluster.manage and .approve,
// stores the digest of a preapproved key of a private_tofu cluster and
// records kubernetes_join_key.preapproved_issued.
func (store *KubernetesClusterStore) IssueInstallToken(ctx context.Context, issue kubecluster.InstallTokenIssue) (
	kubecluster.JoinKey, error) {
	if !issue.Token.IsValid() || !issue.KeyID.IsValid() || !issue.PreapprovalID.IsValid() {
		return kubecluster.JoinKey{}, kubecluster.ErrInvalid
	}
	digest, err := store.keyring.Digest(issue.Session.DeploymentID(), issue.Session.DeploymentRecoveryEpoch(),
		issue.Token)
	if err != nil {
		return kubecluster.JoinKey{}, kubecluster.ErrInvalid
	}
	digestBytes, fingerprint := digest.Bytes(), digest.Fingerprint()
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.JoinKey{}, kubecluster.ErrUnavailable
	}
	scope := issue.Scope
	var key kubecluster.JoinKey
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, issueKubernetesInstallTokenSQL, append(sessionQueryArguments(issue.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), issue.ClusterID.String(),
			issue.KeyID.String(), issue.PreapprovalID.String(), digest.KeyID().String(), digestBytes[:],
			fingerprint[:], int64(issue.Lifetime/time.Second), issue.Replicas,
			changeID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record kubernetesInstallTokenRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil || record.Cluster == nil ||
			record.NetworkID != scope.NetworkID().String() || record.NetworkRevision <= 0 ||
			record.Preapproval == nil || record.Preapproval.Replicas != issue.Replicas {
			return false, kubecluster.ErrInvalid
		}
		decoded, err := record.Key.key()
		if err != nil || decoded.ID() != issue.KeyID || decoded.State() != kubecluster.KeyActive ||
			decoded.Uses() != issue.Replicas || decoded.ExpiresAt().Sub(decoded.CreatedAt()) != issue.Lifetime ||
			record.Cluster.ClusterID != issue.ClusterID.String() {
			return false, kubecluster.ErrInvalid
		}
		key = decoded
		record.ClusterID = record.Cluster.ClusterID
		return true, store.appendInstallTokenEvent(ctx, tx, issue.Session, issue.CorrelationID, changeID,
			record.kubernetesJoinKeyRecord, issue.Replicas)
	})
	return key, err
}

// appendInstallTokenEvent records kubernetes_join_key.preapproved_issued: a
// join key whose maker approves every replica it admits, told apart from
// an ordinary key in the event itself (action, hash and payload).
func (store *KubernetesClusterStore) appendInstallTokenEvent(ctx context.Context, tx accountSessionTransaction,
	session accountsession.Session, correlationID, changeID publicid.ID, record kubernetesJoinKeyRecord,
	replicas int) error {
	keyID, err := enrollment.ParseCredentialID(record.Key.KeyID)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	const action = "kubernetes_join_key.preapproved_issued"
	after, err := kubernetesSemanticHash(struct {
		NetworkID   string `json:"network_id"`
		ClusterID   string `json:"cluster_id"`
		KeyID       string `json:"key_id"`
		State       string `json:"state"`
		ExpiresAt   string `json:"expires_at"`
		Uses        int    `json:"uses"`
		Preapproved bool   `json:"preapproved"`
		Replicas    int    `json:"replicas"`
	}{record.NetworkID, record.ClusterID, record.Key.KeyID, record.Key.State,
		record.Key.ExpiresAt.UTC().Format(time.RFC3339Nano), record.Key.Uses, true, replicas})
	if err != nil {
		return kubecluster.ErrInvalid
	}
	event := catalogEvent{
		session: session, correlationID: correlationID, changeID: changeID,
		aggregateKind: "enrollment_credential", aggregateID: publicid.ID(keyID),
		version: record.Key.Version, networkVersion: record.NetworkRevision,
		action: action, permission: "kubernetes_cluster.manage", after: after,
		payload: struct {
			NetworkID    string           `json:"network_id"`
			SessionID    string           `json:"session_id"`
			ClusterID    string           `json:"cluster_id"`
			KeyID        string           `json:"key_id"`
			KeyExpiresAt string           `json:"key_expires_at"`
			Uses         int              `json:"uses"`
			Preapproved  bool             `json:"preapproved"`
			Replicas     int              `json:"replicas"`
			Authority    catalogAuthority `json:"authority"`
		}{record.NetworkID, session.ID().String(), record.ClusterID, record.Key.KeyID,
			record.Key.ExpiresAt.UTC().Format(time.RFC3339), record.Key.Uses, true, replicas, record.Authority},
		outboxClass: action,
		outbox: struct {
			NetworkID string `json:"network_id"`
			ClusterID string `json:"cluster_id"`
			KeyID     string `json:"key_id"`
			Version   int64  `json:"version"`
		}{record.NetworkID, record.ClusterID, record.Key.KeyID, record.Key.Version},
	}
	if err := appendNetworkMemberEvent(ctx, tx, event); err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	return nil
}

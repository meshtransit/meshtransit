package postgres

import (
	"context"
	"encoding/hex"
	"errors"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

const replaceKubernetesClusterSigningTrustSQL = `SELECT mesh_ops.replace_kubernetes_cluster_signing_trust_v1(` +
	sessionArguments + `,$10::UUID,$11::UUID,$12::UUID,$13::BIGINT,$14::TEXT,$15::BYTEA,$16::BYTEA[],$17::TEXT,
 $18::TEXT,$19::TEXT,$20::TEXT,$21::UUID,$22::UUID)::TEXT`

// trustReplacementAction is the audit action of a pasted trust.
const trustReplacementAction = "kubernetes_cluster.signing_trust_replaced"

type kubernetesTrustReplacementRecord struct {
	NetworkID       string                          `json:"network_id"`
	ClusterID       string                          `json:"cluster_id"`
	Changed         bool                            `json:"changed"`
	NetworkRevision *int64                          `json:"network_revision"`
	Authority       catalogAuthority                `json:"authority"`
	Before          *kubernetesSigningTrustDocument `json:"before"`
	Trust           kubernetesSigningTrustDocument  `json:"trust"`
}

// ReplaceSigningTrust authorizes kubernetes_cluster.manage and
// kubernetes_cluster.approve, sets or replaces the cluster's signing trust
// and records kubernetes_cluster.signing_trust_replaced (schema 235). The
// trust already sent changes and records nothing.
func (store *KubernetesClusterStore) ReplaceSigningTrust(ctx context.Context,
	replacement kubecluster.TrustReplacement) (kubecluster.TrustReplacementResult, error) {
	trustID, err := publicid.New()
	if err != nil {
		return kubecluster.TrustReplacementResult{}, kubecluster.ErrUnavailable
	}
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.TrustReplacementResult{}, kubecluster.ErrUnavailable
	}
	keys := kubecluster.TrustKeysOf(replacement.JWKS)
	thumbprints := make([][]byte, 0, len(keys))
	for _, key := range keys {
		thumbprints = append(thumbprints, key.Thumbprint[:])
	}
	scope := replacement.Scope
	var result kubecluster.TrustReplacementResult
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, replaceKubernetesClusterSigningTrustSQL, append(
			sessionQueryArguments(replacement.Session), scope.WorkspaceID().String(), scope.NetworkID().String(),
			replacement.ClusterID.String(), replacement.ExpectedVersion, replacement.Issuer,
			replacement.JWKS.Canonical(), thumbprints, replacement.Namespace, replacement.ServiceAccount,
			replacement.StatefulSet, replacement.Reason, trustID.String(), changeID.String())...,
		).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record kubernetesTrustReplacementRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil ||
			record.NetworkID != scope.NetworkID().String() || record.ClusterID != replacement.ClusterID.String() {
			return false, kubecluster.ErrInvalid
		}
		trust, err := record.Trust.trust()
		if err != nil {
			return false, err
		}
		result = kubecluster.TrustReplacementResult{Changed: record.Changed, Trust: trust}
		if !record.Changed {
			// Nothing written: the trust already was this one.
			if record.Before != nil || record.NetworkRevision != nil {
				return false, kubecluster.ErrInvalid
			}
			return false, nil
		}
		if record.NetworkRevision == nil || *record.NetworkRevision < 1 ||
			trust.Source != kubecluster.TrustFromAdminPaste || (record.Before == nil) != (trust.Version == 1) ||
			record.Before == nil && record.Trust.TrustID != trustID.String() {
			return false, kubecluster.ErrInvalid
		}
		if record.Before != nil {
			// A replaced trust keeps its ID across versions.
			previous, err := record.Before.trust()
			if err != nil || previous.Version+1 != trust.Version || record.Before.TrustID != record.Trust.TrustID {
				return false, kubecluster.ErrInvalid
			}
			result.Previous = &previous
		}
		return true, store.appendTrustReplacementEvent(ctx, tx, replacement, changeID, record, result)
	})
	return result, err
}

type trustKeyAudit struct {
	KeyID           string `json:"kid"`
	KubernetesKeyID string `json:"computed_kid"`
	Thumbprint      string `json:"thumbprint"`
	Type            string `json:"kty"`
}

type trustIdentityAudit struct {
	Issuer         string          `json:"issuer"`
	Namespace      string          `json:"namespace"`
	ServiceAccount string          `json:"service_account"`
	StatefulSet    string          `json:"statefulset"`
	Keys           []trustKeyAudit `json:"keys"`
}

func auditTrust(trust kubecluster.SigningTrust) trustIdentityAudit {
	keys := make([]trustKeyAudit, 0, len(trust.Keys))
	for _, key := range trust.Keys {
		keys = append(keys, trustKeyAudit{KeyID: key.KeyID, KubernetesKeyID: key.KubernetesKeyID,
			Thumbprint: hex.EncodeToString(key.Thumbprint[:]), Type: key.Type})
	}
	return trustIdentityAudit{Issuer: trust.Issuer, Namespace: trust.Namespace,
		ServiceAccount: trust.ServiceAccount, StatefulSet: trust.StatefulSet, Keys: keys}
}

// appendTrustReplacementEvent records the replacement on the Network's
// stream: the trust before and after by key names and thumbprints, never
// the keys themselves, the kids that differ from the ones Kubernetes
// computes, and the reason (K1.1b §5).
func (store *KubernetesClusterStore) appendTrustReplacementEvent(ctx context.Context, tx accountSessionTransaction,
	replacement kubecluster.TrustReplacement, changeID publicid.ID, record kubernetesTrustReplacementRecord,
	result kubecluster.TrustReplacementResult) error {
	after := auditTrust(result.Trust)
	afterHash, err := kubernetesSemanticHash(struct {
		NetworkID string             `json:"network_id"`
		ClusterID string             `json:"cluster_id"`
		Version   int64              `json:"version"`
		Trust     trustIdentityAudit `json:"trust"`
	}{record.NetworkID, record.ClusterID, result.Trust.Version, after})
	if err != nil {
		return kubecluster.ErrInvalid
	}
	var previous *trustIdentityAudit
	var previousVersion *int64
	// The trust is its own aggregate, versioned on its own; the cluster is in the payload.
	trustID, err := publicid.Parse(record.Trust.TrustID)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	mismatched := kubecluster.KeyIDMismatches(result.Trust.Keys)
	if mismatched == nil {
		mismatched = []string{}
	}
	event := catalogEvent{
		session: replacement.Session, correlationID: replacement.CorrelationID, changeID: changeID,
		aggregateKind: "kubernetes_cluster_signing_trust", aggregateID: trustID,
		version: result.Trust.Version, networkVersion: *record.NetworkRevision,
		action: trustReplacementAction, permission: "kubernetes_cluster.approve", after: afterHash,
		outboxClass: trustReplacementAction,
		outbox: struct {
			NetworkID string `json:"network_id"`
			ClusterID string `json:"cluster_id"`
			Version   int64  `json:"version"`
		}{record.NetworkID, record.ClusterID, result.Trust.Version},
	}
	if result.Previous != nil {
		before := auditTrust(*result.Previous)
		previous, previousVersion = &before, &result.Previous.Version
		beforeHash, err := kubernetesSemanticHash(struct {
			NetworkID string             `json:"network_id"`
			ClusterID string             `json:"cluster_id"`
			Version   int64              `json:"version"`
			Trust     trustIdentityAudit `json:"trust"`
		}{record.NetworkID, record.ClusterID, result.Previous.Version, before})
		if err != nil {
			return kubecluster.ErrInvalid
		}
		event.before = &beforeHash
	}
	event.payload = struct {
		NetworkID       string              `json:"network_id"`
		SessionID       string              `json:"session_id"`
		ClusterID       string              `json:"cluster_id"`
		TrustID         string              `json:"trust_id"`
		Version         int64               `json:"version"`
		PreviousVersion *int64              `json:"previous_version"`
		Trust           trustIdentityAudit  `json:"trust"`
		Previous        *trustIdentityAudit `json:"previous"`
		KeyIDMismatch   []string            `json:"kid_mismatch"`
		Reason          string              `json:"reason"`
		Authority       catalogAuthority    `json:"authority"`
	}{record.NetworkID, replacement.Session.ID().String(), record.ClusterID, record.Trust.TrustID,
		result.Trust.Version, previousVersion, after, previous, mismatched, replacement.Reason, record.Authority}
	if err := appendNetworkMemberEvent(ctx, tx, event); err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	return nil
}

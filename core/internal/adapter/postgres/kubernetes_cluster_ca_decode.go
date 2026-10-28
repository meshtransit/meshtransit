package postgres

import (
	"encoding/hex"
	"time"

	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/publicid"
)

// clusterCAMaximumLive bounds a cluster's CAs that are not retired: three
// roots, one active intermediate and the retiring ones whose certificates
// may still live.
const clusterCAMaximumLive = 16

// The database refuses a ninth retiring intermediate, so a cluster has at
// most three roots, one active intermediate and eight retiring ones.

type clusterCADataKeyRecord struct {
	ID         string `json:"id"`
	Version    int64  `json:"version"`
	Active     bool   `json:"active"`
	Custody    string `json:"custody"`
	KeyID      string `json:"key_id"`
	Ciphertext string `json:"ciphertext"`
}

type clusterCARecord struct {
	ID             string     `json:"id"`
	Version        int64      `json:"version"`
	Kind           string     `json:"kind"`
	IssuerID       *string    `json:"issuer_id"`
	State          string     `json:"state"`
	Reason         string     `json:"reason"`
	DataKeyID      string     `json:"data_key_id"`
	Certificate    string     `json:"certificate"`
	ClusterDNSName string     `json:"cluster_dns_name"`
	NotBefore      time.Time  `json:"not_before"`
	NotAfter       time.Time  `json:"not_after"`
	SealedKey      *string    `json:"sealed_key"`
	CreatedAt      time.Time  `json:"created_at"`
	ActivatedAt    *time.Time `json:"activated_at"`
	RetiringAt     *time.Time `json:"retiring_at"`
}

type clusterCAClusterRecord struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	State        string            `json:"state"`
	NextActionAt time.Time         `json:"next_action_at"`
	Failures     int               `json:"failures"`
	CAs          []clusterCARecord `json:"cas"`
}

// decodeClusterCANetwork decodes what read_kubernetes_ca_network_v1 or
// lock_kubernetes_ca_network_v2 returned, with its outcome: read, locked
// or busy (with nothing read).
func decodeClusterCANetwork(encoded string) (kubeca.Network, string, error) {
	var record struct {
		Outcome       string                   `json:"outcome"`
		Now           time.Time                `json:"now"`
		WorkspaceCode *string                  `json:"workspace_code"`
		NetworkCode   *string                  `json:"network_code"`
		DataKeys      []clusterCADataKeyRecord `json:"data_keys"`
		Clusters      []clusterCAClusterRecord `json:"clusters"`
	}
	if err := decodeStrictJSON(encoded, clusterCAMaximumNetwork, &record); err != nil {
		return kubeca.Network{}, "", ErrKubernetesClusterCAStore
	}
	if record.Outcome == "busy" && record.DataKeys == nil && record.Clusters == nil {
		return kubeca.Network{}, "busy", nil
	}
	if record.Outcome != "locked" && record.Outcome != "read" || record.Now.IsZero() ||
		record.WorkspaceCode == nil || record.NetworkCode == nil || record.DataKeys == nil || record.Clusters == nil {
		return kubeca.Network{}, "", ErrKubernetesClusterCAStore
	}
	read := kubeca.Network{
		Now: record.Now, WorkspaceCode: *record.WorkspaceCode, NetworkCode: *record.NetworkCode,
		DataKeys: make([]kubeca.StoredDataKey, 0, len(record.DataKeys)),
		Clusters: make([]kubeca.Cluster, 0, len(record.Clusters)),
	}
	for _, item := range record.DataKeys {
		key, err := decodeClusterCADataKey(item)
		if err != nil {
			return kubeca.Network{}, "", err
		}
		read.DataKeys = append(read.DataKeys, key)
	}
	for _, item := range record.Clusters {
		cluster, err := decodeClusterCACluster(item)
		if err != nil {
			return kubeca.Network{}, "", err
		}
		read.Clusters = append(read.Clusters, cluster)
	}
	return read, record.Outcome, nil
}

func decodeClusterCADataKey(record clusterCADataKeyRecord) (kubeca.StoredDataKey, error) {
	id, idErr := publicid.Parse(record.ID)
	ciphertext, ciphertextErr := hex.DecodeString(record.Ciphertext)
	if idErr != nil || ciphertextErr != nil || len(ciphertext) == 0 || record.KeyID == "" || record.Version < 1 ||
		record.Custody != "file" && record.Custody != "kms" {
		return kubeca.StoredDataKey{}, ErrKubernetesClusterCAStore
	}
	return kubeca.StoredDataKey{
		ID: id, Version: record.Version, Active: record.Active,
		Wrapped: kubeca.WrappedKey{Custody: record.Custody, KeyID: record.KeyID, Ciphertext: ciphertext},
	}, nil
}

func decodeClusterCACluster(record clusterCAClusterRecord) (kubeca.Cluster, error) {
	id, err := publicid.Parse(record.ID)
	if err != nil || record.Name == "" || record.State != "active" && record.State != "deleted" ||
		record.NextActionAt.IsZero() || record.Failures < 0 || record.CAs == nil ||
		len(record.CAs) > clusterCAMaximumLive {
		return kubeca.Cluster{}, ErrKubernetesClusterCAStore
	}
	cluster := kubeca.Cluster{
		ID: id, Name: record.Name, Active: record.State == "active",
		NextActionAt: record.NextActionAt, Failures: record.Failures, CAs: make([]kubeca.StoredCA, 0, len(record.CAs)),
	}
	for _, item := range record.CAs {
		ca, err := decodeClusterCA(item)
		if err != nil {
			return kubeca.Cluster{}, err
		}
		cluster.CAs = append(cluster.CAs, ca)
	}
	return cluster, nil
}

// decodeClusterCA checks a stored CA is one the schema allows: a root (no
// issuer), or an intermediate (an issuer, never next); a sealed key exactly
// while it signs or is published.
func decodeClusterCA(record clusterCARecord) (kubeca.StoredCA, error) {
	id, idErr := publicid.Parse(record.ID)
	dataKey, dataKeyErr := publicid.Parse(record.DataKeyID)
	certificate, certificateErr := hex.DecodeString(record.Certificate)
	kind, kindOK := kubeca.ParseKind(record.Kind)
	state := kubeca.State(record.State)
	reason := kubeca.Reason(record.Reason)
	signing := state == kubeca.StateNext || state == kubeca.StateActive
	if idErr != nil || dataKeyErr != nil || certificateErr != nil || len(certificate) == 0 || record.Version < 1 ||
		!kindOK || (kind == kubeca.KindRoot) != (record.IssuerID == nil) ||
		!signing && state != kubeca.StateRetiring || kind == kubeca.KindIntermediate && state == kubeca.StateNext ||
		!reason.CreatesCA() || record.ClusterDNSName == "" || !record.NotAfter.After(record.NotBefore) ||
		record.CreatedAt.IsZero() || (record.SealedKey != nil) != signing ||
		(record.ActivatedAt != nil) != (state == kubeca.StateActive || state == kubeca.StateRetiring) ||
		(record.RetiringAt != nil) != (state == kubeca.StateRetiring) {
		return kubeca.StoredCA{}, ErrKubernetesClusterCAStore
	}
	ca := kubeca.StoredCA{
		ID: id, Version: record.Version, Kind: kind, State: state, Reason: reason, DataKeyID: dataKey,
		Certificate: certificate, ClusterDNSName: record.ClusterDNSName, NotBefore: record.NotBefore,
		NotAfter: record.NotAfter, CreatedAt: record.CreatedAt,
	}
	if record.IssuerID != nil {
		issuer, err := publicid.Parse(*record.IssuerID)
		if err != nil {
			return kubeca.StoredCA{}, ErrKubernetesClusterCAStore
		}
		ca.IssuerID = issuer
	}
	if record.SealedKey != nil {
		sealed, err := hex.DecodeString(*record.SealedKey)
		if err != nil || len(sealed) == 0 {
			return kubeca.StoredCA{}, ErrKubernetesClusterCAStore
		}
		ca.SealedKey = sealed
	}
	if record.ActivatedAt != nil {
		ca.ActivatedAt = *record.ActivatedAt
	}
	if record.RetiringAt != nil {
		ca.RetiringAt = *record.RetiringAt
	}
	return ca, nil
}

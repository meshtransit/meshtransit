package postgres

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// Schema 248 (K1d d1b): pages and single rows of a cluster's replicas and
// certificate authorities, for any reader of the Network.
const (
	listKubernetesReplicasSQL = `SELECT mesh_ops.list_kubernetes_cluster_replicas_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TIMESTAMPTZ,$14::UUID,$15::INTEGER)::TEXT`
	readKubernetesReplicaSQL = `SELECT mesh_ops.read_kubernetes_cluster_replica_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::UUID)::TEXT`
	listKubernetesCAsSQL = `SELECT mesh_ops.list_kubernetes_cluster_cas_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TIMESTAMPTZ,$14::UUID,$15::INTEGER)::TEXT`
	readKubernetesCASQL = `SELECT mesh_ops.read_kubernetes_cluster_ca_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::UUID)::TEXT`
)

type kubernetesReplicaPageDocument struct {
	kubernetesReplicaDocument
	TokenFirstProvenAt *time.Time `json:"token_first_proven_at"`
}

func (document kubernetesReplicaPageDocument) replica() (kubecluster.Replica, error) {
	deviceID, err := node.ParseID(document.DeviceID)
	if err != nil || document.Ordinal < 0 || document.Ordinal > kubecluster.MaximumOrdinal ||
		document.CreatedAt.IsZero() || document.Name == "" || document.State == "" {
		return kubecluster.Replica{}, kubecluster.ErrInvalid
	}
	replica := kubecluster.Replica{DeviceID: deviceID, Name: document.Name, Ordinal: document.Ordinal,
		State: document.State, CreatedAt: document.CreatedAt.UTC()}
	if document.TokenFirstProvenAt != nil {
		replica.TokenFirstProvenAt = document.TokenFirstProvenAt.UTC()
	}
	return replica, nil
}

type kubernetesCADocument struct {
	CAID              string     `json:"ca_id"`
	Kind              string     `json:"kind"`
	IssuerCAID        *string    `json:"issuer_ca_id"`
	State             string     `json:"state"`
	Reason            string     `json:"reason"`
	StateReason       string     `json:"state_reason"`
	Fingerprint       string     `json:"fingerprint"`
	Certificate       string     `json:"certificate"`
	ClusterDNSName    string     `json:"cluster_dns_name"`
	NotBefore         time.Time  `json:"not_before"`
	NotAfter          time.Time  `json:"not_after"`
	CreatedAt         time.Time  `json:"created_at"`
	ActivatedAt       *time.Time `json:"activated_at"`
	RetiringAt        *time.Time `json:"retiring_at"`
	RetiredAt         *time.Time `json:"retired_at"`
	ChangedByOperator bool       `json:"changed_by_operator"`
	Version           int64      `json:"version"`
}

func (document kubernetesCADocument) ca() (kubecluster.CertificateAuthority, error) {
	invalid := kubecluster.ErrInvalid
	id, err := publicid.Parse(document.CAID)
	if err != nil || !id.IsValid() {
		return kubecluster.CertificateAuthority{}, invalid
	}
	// PostgreSQL's base64 breaks lines every 76 characters.
	certificate, err := base64.StdEncoding.DecodeString(stripNewlines(document.Certificate))
	fingerprint, fingerprintErr := hex.DecodeString(document.Fingerprint)
	kind := kubecluster.CAKind(document.Kind)
	if err != nil || fingerprintErr != nil || len(fingerprint) != 32 || len(certificate) == 0 ||
		(kind != kubecluster.CARoot && kind != kubecluster.CAIntermediate) ||
		(kind == kubecluster.CAIntermediate) != (document.IssuerCAID != nil) || document.Version < 1 ||
		!document.NotAfter.After(document.NotBefore) || document.CreatedAt.IsZero() {
		return kubecluster.CertificateAuthority{}, invalid
	}
	ca := kubecluster.CertificateAuthority{ID: id, Kind: kind, State: document.State, Reason: document.Reason,
		StateReason: document.StateReason, Fingerprint: document.Fingerprint, Certificate: certificate,
		ClusterDNSName: document.ClusterDNSName, NotBefore: document.NotBefore.UTC(),
		NotAfter: document.NotAfter.UTC(), CreatedAt: document.CreatedAt.UTC(),
		ChangedByOperator: document.ChangedByOperator, Version: document.Version}
	if document.IssuerCAID != nil {
		if ca.IssuerID, err = publicid.Parse(*document.IssuerCAID); err != nil {
			return kubecluster.CertificateAuthority{}, invalid
		}
	}
	for _, pair := range []struct {
		from *time.Time
		to   *time.Time
	}{{document.ActivatedAt, &ca.ActivatedAt}, {document.RetiringAt, &ca.RetiringAt},
		{document.RetiredAt, &ca.RetiredAt}} {
		if pair.from != nil {
			*pair.to = pair.from.UTC()
		}
	}
	return ca, nil
}

func stripNewlines(value string) string {
	out := make([]byte, 0, len(value))
	for index := range len(value) {
		if value[index] != '\n' && value[index] != '\r' {
			out = append(out, value[index])
		}
	}
	return string(out)
}

// ListReplicas reads a page of a cluster's replicas.
func (store *KubernetesClusterStore) ListReplicas(ctx context.Context,
	query kubecluster.PageQuery) (kubecluster.ReplicaPage, error) {
	var documents []kubernetesReplicaPageDocument
	if err := store.readPage(ctx, listKubernetesReplicasSQL, query, &documents); err != nil {
		return kubecluster.ReplicaPage{}, err
	}
	if documents == nil || len(documents) > query.Limit+1 {
		return kubecluster.ReplicaPage{}, kubecluster.ErrInvalid
	}
	page := kubecluster.ReplicaPage{Replicas: make([]kubecluster.Replica, 0, min(len(documents), query.Limit))}
	previous := query.After
	for _, document := range documents[:min(len(documents), query.Limit)] {
		replica, err := document.replica()
		if err != nil {
			return kubecluster.ReplicaPage{}, err
		}
		at, id := replica.CreatedAt, publicid.ID(replica.DeviceID)
		if !beforeCursor(previous, at, id) {
			return kubecluster.ReplicaPage{}, kubecluster.ErrInvalid
		}
		previous = kubecluster.PageCursor{At: at, ID: id}
		page.Replicas = append(page.Replicas, replica)
	}
	if len(documents) > query.Limit {
		page.Next = previous
	}
	return page, nil
}

// ReadReplica reads one of a cluster's replicas.
func (store *KubernetesClusterStore) ReadReplica(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID, deviceID node.ID) (kubecluster.Replica, error) {
	var replica kubecluster.Replica
	err := store.readOne(ctx, readKubernetesReplicaSQL, session, scope, clusterID, deviceID.String(),
		func(encoded []byte) error {
			var document kubernetesReplicaPageDocument
			if err := decodeIdentityCatalogJSON(encoded, &document); err != nil {
				return kubecluster.ErrInvalid
			}
			read, err := document.replica()
			if err != nil || read.DeviceID != deviceID {
				return kubecluster.ErrInvalid
			}
			replica = read
			return nil
		})
	return replica, err
}

// ListCertificateAuthorities reads a page of a cluster's CAs.
func (store *KubernetesClusterStore) ListCertificateAuthorities(ctx context.Context,
	query kubecluster.PageQuery) (kubecluster.CAPage, error) {
	var documents []kubernetesCADocument
	if err := store.readPage(ctx, listKubernetesCAsSQL, query, &documents); err != nil {
		return kubecluster.CAPage{}, err
	}
	if documents == nil || len(documents) > query.Limit+1 {
		return kubecluster.CAPage{}, kubecluster.ErrInvalid
	}
	page := kubecluster.CAPage{CAs: make([]kubecluster.CertificateAuthority, 0, min(len(documents), query.Limit))}
	previous := query.After
	for _, document := range documents[:min(len(documents), query.Limit)] {
		ca, err := document.ca()
		if err != nil {
			return kubecluster.CAPage{}, err
		}
		if !beforeCursor(previous, ca.CreatedAt, ca.ID) {
			return kubecluster.CAPage{}, kubecluster.ErrInvalid
		}
		previous = kubecluster.PageCursor{At: ca.CreatedAt, ID: ca.ID}
		page.CAs = append(page.CAs, ca)
	}
	if len(documents) > query.Limit {
		page.Next = previous
	}
	return page, nil
}

// ReadCertificateAuthority reads one of a cluster's CAs.
func (store *KubernetesClusterStore) ReadCertificateAuthority(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID, caID publicid.ID) (kubecluster.CertificateAuthority, error) {
	var ca kubecluster.CertificateAuthority
	err := store.readOne(ctx, readKubernetesCASQL, session, scope, clusterID, caID.String(),
		func(encoded []byte) error {
			var document kubernetesCADocument
			if err := decodeIdentityCatalogJSON(encoded, &document); err != nil {
				return kubecluster.ErrInvalid
			}
			read, err := document.ca()
			if err != nil || read.ID != caID {
				return kubecluster.ErrInvalid
			}
			ca = read
			return nil
		})
	return ca, err
}

// readOne runs one single-row read of a cluster's child.
func (store *KubernetesClusterStore) readOne(ctx context.Context, sql string, session accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID, childID string, decode func([]byte) error) error {
	return store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, sql, append(sessionQueryArguments(session), scope.WorkspaceID().String(),
			scope.NetworkID().String(), clusterID.String(), childID)...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		return false, decode([]byte(encoded))
	})
}

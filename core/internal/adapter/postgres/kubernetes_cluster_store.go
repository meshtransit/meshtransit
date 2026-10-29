package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/kubejoin"
)

const (
	createKubernetesClusterSQL = `SELECT mesh_ops.create_kubernetes_cluster_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::TEXT,$14::TEXT,$15::INTEGER,$16::UUID)::TEXT`
	deleteKubernetesClusterSQL = `SELECT mesh_ops.delete_kubernetes_cluster_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::BIGINT,$14::UUID)::TEXT`
	listKubernetesClustersSQL = `SELECT mesh_ops.list_kubernetes_clusters_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::INTEGER)::TEXT`
	readKubernetesClusterSQL = `SELECT mesh_ops.read_kubernetes_cluster_v2(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::INTEGER,$14::INTEGER)::TEXT`
	issueKubernetesJoinKeySQL = `SELECT mesh_ops.issue_kubernetes_join_key_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::UUID,$14::TEXT,$15::BYTEA,$16::BYTEA,$17::BIGINT,$18::BIGINT,$19::UUID)::TEXT`
	revokeKubernetesJoinKeySQL = `SELECT mesh_ops.revoke_kubernetes_join_key_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::UUID,$14::UUID)::TEXT`
	lockKubernetesReplicaRequestSQL = `SELECT mesh_ops.lock_kubernetes_replica_request_v2(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::UUID,$14::UUID)::TEXT`
	approveKubernetesReplicaRequestSQL = `SELECT mesh_ops.approve_kubernetes_replica_request_v2(` +
		sessionArguments + `,$10::UUID,$11::UUID,$12::UUID,$13::UUID,$15::BIGINT,$14::UUID)::TEXT`
	recordKubernetesJoinCodeFailureSQL = `SELECT mesh_ops.record_kubernetes_join_code_failure_v2(` +
		sessionArguments + `,$10::UUID,$11::UUID,$12::UUID,$13::UUID,$14::UUID)::TEXT`
	rejectKubernetesReplicaRequestSQL = `SELECT mesh_ops.reject_kubernetes_replica_request_v1(` +
		sessionArguments + `,$10::UUID,$11::UUID,$12::UUID,$13::UUID,$14::UUID)::TEXT`
)

// KubernetesClusterStore manages the Kubernetes clusters of one Network
// through the runtime pool (K1a1 plan §2). It digests each new join key with
// the active enrollment keyring and stores only the digest; approvals
// compare the typed code with the request's in the transaction that records
// the outcome; every change commits with one event on the Network's stream.
type KubernetesClusterStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
	keyring  *enrollment.CredentialKeyring
}

var _ kubecluster.Store = (*KubernetesClusterStore)(nil)

// NewKubernetesClusterStore uses the runtime pool and the enrollment keyring.
func NewKubernetesClusterStore(pool *Pool, options AccountSessionOptions,
	keyring *enrollment.CredentialKeyring) (*KubernetesClusterStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) || keyring == nil {
		return nil, kubecluster.ErrInvalid
	}
	return &KubernetesClusterStore{database: pool.workspaceRenameDatabase, options: options, keyring: keyring}, nil
}

func (store *KubernetesClusterStore) transact(ctx context.Context, scope network.Scope,
	run func(tx accountSessionTransaction) (bool, error)) (resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) {
		return kubecluster.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setResourceAuthorityScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil {
		return kubernetesClusterDatabaseError(err)
	}
	if workspaceInternal <= 0 || networkInternal <= 0 {
		return kubecluster.ErrForbidden
	}
	commit, err := run(tx)
	if err != nil || !commit {
		return err
	}
	committed = true
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	return nil
}

func kubernetesClusterDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501", "23503":
			return kubecluster.ErrForbidden
		case "P0002":
			return kubecluster.ErrNotFound
		// MTL01: a gateway Device cannot take part; 40P01: a deadlock, which
		// a retry resolves.
		case "40001", "40P01", "23505", "MTL01", "MTK05", "MTK08":
			return kubecluster.ErrConflict
		case "MTK02":
			return kubecluster.ErrNotWaiting
		case "MTK04":
			return kubecluster.ErrKeyNotUsable
		case "MTK07":
			return kubecluster.ErrLimitReached
		// MTD06: a rule to the cluster would give a Device too many edges;
		// DETAIL names a source Device, empty for the new replica.
		case "MTD06":
			source, _ := node.ParseID(pgError.Detail)
			return &kubecluster.EdgeBudgetError{SourceDeviceID: source}
		case "22023", "22P02", "23514", "MTK09":
			return kubecluster.ErrInvalid
		// Schema 232: the request has no trust, its trust differs from the
		// cluster's, or its pod is held.
		case "MTK14":
			return kubecluster.ErrJoinAgain
		case "MTK15":
			return kubecluster.ErrSigningMismatch
		case "MTK16":
			return kubecluster.ErrPodHeld
		// Schema 235: the trust's version moved, or replicas still run under
		// its identity.
		case "MTK21":
			return kubecluster.ErrTrustChanged
		case "MTK22":
			return kubecluster.ErrIdentityBound
		// Schema 252: the CA is retired already, another reason waits, or
		// the person asked too often.
		case "MTK40":
			return kubecluster.ErrCARetired
		case "MTK41":
			return kubecluster.ErrRetirePending
		case "MTK42":
			return kubecluster.ErrRetireRateLimited
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return kubecluster.ErrForbidden
	}
	return errors.Join(kubecluster.ErrUnavailable, err)
}

type kubernetesClusterDocument struct {
	ClusterID    string    `json:"cluster_id"`
	Name         string    `json:"name"`
	Description  *string   `json:"description"`
	State        string    `json:"state"`
	Version      int64     `json:"version"`
	CreatedBy    string    `json:"created_by_principal_id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	ReplicaCount int       `json:"replicas"`
}

func (document kubernetesClusterDocument) cluster() (kubecluster.Cluster, error) {
	id, err := kubecluster.ParseID(document.ClusterID)
	if err != nil {
		return kubecluster.Cluster{}, kubecluster.ErrInvalid
	}
	name, err := kubecluster.ParseName(document.Name)
	if err != nil {
		return kubecluster.Cluster{}, kubecluster.ErrInvalid
	}
	creator, err := identity.ParsePrincipalID(document.CreatedBy)
	if err != nil {
		return kubecluster.Cluster{}, kubecluster.ErrInvalid
	}
	params := kubecluster.ClusterParams{
		ID: id, Name: name, State: kubecluster.State(document.State), Version: document.Version,
		Replicas: document.ReplicaCount, CreatedBy: creator, CreatedAt: document.CreatedAt,
		UpdatedAt: document.UpdatedAt,
	}
	if document.Description != nil {
		params.Description = *document.Description
	}
	return kubecluster.NewCluster(params)
}

type kubernetesJoinKeyDocument struct {
	KeyID     string     `json:"key_id"`
	IssuedBy  string     `json:"issued_by_principal_id"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt time.Time  `json:"expires_at"`
	RevokedAt *time.Time `json:"revoked_at"`
	Uses      int        `json:"uses"`
	Used      int        `json:"used"`
	Version   int64      `json:"version"`
	State     string     `json:"state"`
}

func (document kubernetesJoinKeyDocument) key() (kubecluster.JoinKey, error) {
	id, err := enrollment.ParseCredentialID(document.KeyID)
	if err != nil {
		return kubecluster.JoinKey{}, kubecluster.ErrInvalid
	}
	issuer, err := identity.ParsePrincipalID(document.IssuedBy)
	if err != nil {
		return kubecluster.JoinKey{}, kubecluster.ErrInvalid
	}
	params := kubecluster.JoinKeyParams{
		ID: id, IssuedBy: issuer, CreatedAt: document.CreatedAt, ExpiresAt: document.ExpiresAt,
		Uses: document.Uses, Used: document.Used, State: kubecluster.KeyState(document.State),
		Version: document.Version,
	}
	if document.RevokedAt != nil {
		params.RevokedAt = *document.RevokedAt
	}
	return kubecluster.NewJoinKey(params)
}

type kubernetesReplicaRequestDocument struct {
	RequestID          string          `json:"request_id"`
	ClusterID          string          `json:"cluster_id"`
	KeyID              string          `json:"key_id"`
	MachineFingerprint string          `json:"machine_key_fingerprint"`
	NodeFingerprint    string          `json:"node_key_fingerprint"`
	Hostname           string          `json:"hostname"`
	Reported           json.RawMessage `json:"reported"`
	State              string          `json:"state"`
	FailedAttempts     int             `json:"failed_code_attempts"`
	ApprovedBy         *string         `json:"approved_by_principal_id"`
	ApprovedAt         *time.Time      `json:"approved_at"`
	CompletionDeadline *time.Time      `json:"completion_deadline"`
	ReservedOrdinal    *int            `json:"reserved_ordinal"`
	ReservedHostname   *string         `json:"reserved_hostname"`
	DeviceID           *string         `json:"device_id"`
	ExpiresAt          time.Time       `json:"expires_at"`
	Version            int64           `json:"version"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

func (document kubernetesReplicaRequestDocument) view() (kubecluster.ReplicaRequestView, error) {
	requestID, err := kubecluster.ParseRequestID(document.RequestID)
	if err != nil {
		return kubecluster.ReplicaRequestView{}, kubecluster.ErrInvalid
	}
	clusterID, err := kubecluster.ParseID(document.ClusterID)
	if err != nil {
		return kubecluster.ReplicaRequestView{}, kubecluster.ErrInvalid
	}
	keyID, err := enrollment.ParseCredentialID(document.KeyID)
	if err != nil {
		return kubecluster.ReplicaRequestView{}, kubecluster.ErrInvalid
	}
	lifecycle, err := kubecluster.NewRequest(kubecluster.RequestParams{
		State: kubecluster.RequestState(document.State), FailedAttempts: document.FailedAttempts,
		CreatedAt: document.CreatedAt, ExpiresAt: document.ExpiresAt,
	})
	if err != nil {
		return kubecluster.ReplicaRequestView{}, err
	}
	params := kubecluster.ReplicaRequestParams{
		ID: requestID, ClusterID: clusterID, KeyID: keyID, MachineFingerprint: document.MachineFingerprint,
		NodeFingerprint: document.NodeFingerprint, Hostname: document.Hostname, Reported: document.Reported,
		Lifecycle: lifecycle, Version: document.Version, UpdatedAt: document.UpdatedAt,
	}
	if document.ApprovedBy != nil {
		if params.ApprovedBy, err = identity.ParsePrincipalID(*document.ApprovedBy); err != nil {
			return kubecluster.ReplicaRequestView{}, kubecluster.ErrInvalid
		}
	}
	if document.ApprovedAt != nil && document.CompletionDeadline != nil {
		params.ApprovedAt, params.CompletionDeadline = *document.ApprovedAt, *document.CompletionDeadline
	}
	if document.ReservedOrdinal != nil && document.ReservedHostname != nil {
		params.ReservedOrdinal, params.ReservedHostname = *document.ReservedOrdinal, *document.ReservedHostname
	}
	if document.DeviceID != nil {
		if params.DeviceID, err = node.ParseID(*document.DeviceID); err != nil {
			return kubecluster.ReplicaRequestView{}, kubecluster.ErrInvalid
		}
	}
	return kubecluster.NewReplicaRequestView(params)
}

// kubernetesSemanticHash binds an audit event to what changed.
func kubernetesSemanticHash(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	return sha256.Sum256(encoded), err
}

type kubernetesClusterRecord struct {
	NetworkID       string                     `json:"network_id"`
	NetworkRevision int64                      `json:"network_revision"`
	Before          *kubernetesClusterDocument `json:"before"`
	Cluster         kubernetesClusterDocument  `json:"cluster"`
	Authority       catalogAuthority           `json:"authority"`
}

// CreateCluster authorizes kubernetes_cluster.manage, creates the cluster
// and its profile and records kubernetes_cluster.created.
func (store *KubernetesClusterStore) CreateCluster(ctx context.Context, creation kubecluster.Creation) (
	kubecluster.Cluster, error) {
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.Cluster{}, kubecluster.ErrUnavailable
	}
	scope := creation.Scope
	var cluster kubecluster.Cluster
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, createKubernetesClusterSQL, append(sessionQueryArguments(creation.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), creation.ID.String(),
			creation.Name.String(), creation.Description, kubecluster.MaximumClustersPerNetwork,
			changeID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record kubernetesClusterRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil ||
			record.NetworkID != scope.NetworkID().String() || record.NetworkRevision <= 0 {
			return false, kubecluster.ErrInvalid
		}
		decoded, err := record.Cluster.cluster()
		if err != nil || decoded.ID() != creation.ID || decoded.Name() != creation.Name {
			return false, kubecluster.ErrInvalid
		}
		cluster = decoded
		return true, store.appendClusterEvent(ctx, tx, creation.Session, creation.CorrelationID, changeID,
			"kubernetes_cluster.created", record)
	})
	return cluster, err
}

// DeleteCluster authorizes kubernetes_cluster.manage, deletes the cluster,
// its profile and keys and records kubernetes_cluster.deleted.
func (store *KubernetesClusterStore) DeleteCluster(ctx context.Context, deletion kubecluster.Deletion) (
	kubecluster.Cluster, error) {
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.Cluster{}, kubecluster.ErrUnavailable
	}
	var expected any
	if deletion.ExpectedVersion > 0 {
		expected = deletion.ExpectedVersion
	}
	scope := deletion.Scope
	var cluster kubecluster.Cluster
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, deleteKubernetesClusterSQL, append(sessionQueryArguments(deletion.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), deletion.ClusterID.String(), expected,
			changeID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record kubernetesClusterRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil || record.Before == nil ||
			record.NetworkID != scope.NetworkID().String() || record.NetworkRevision <= 0 {
			return false, kubecluster.ErrInvalid
		}
		decoded, err := record.Cluster.cluster()
		if err != nil || decoded.ID() != deletion.ClusterID || decoded.State() != kubecluster.StateDeleted {
			return false, kubecluster.ErrInvalid
		}
		cluster = decoded
		return true, store.appendClusterEvent(ctx, tx, deletion.Session, deletion.CorrelationID, changeID,
			"kubernetes_cluster.deleted", record)
	})
	return cluster, err
}

func (store *KubernetesClusterStore) appendClusterEvent(ctx context.Context, tx accountSessionTransaction,
	session accountsession.Session, correlationID, changeID publicid.ID, action string,
	record kubernetesClusterRecord) error {
	clusterID, err := kubecluster.ParseID(record.Cluster.ClusterID)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	after, err := kubernetesSemanticHash(struct {
		NetworkID string `json:"network_id"`
		ClusterID string `json:"cluster_id"`
		Name      string `json:"name"`
		State     string `json:"state"`
	}{record.NetworkID, record.Cluster.ClusterID, record.Cluster.Name, record.Cluster.State})
	if err != nil {
		return kubecluster.ErrInvalid
	}
	event := catalogEvent{
		session: session, correlationID: correlationID, changeID: changeID,
		aggregateKind: "kubernetes_cluster", aggregateID: publicid.ID(clusterID),
		version: record.Cluster.Version, networkVersion: record.NetworkRevision,
		action: action, permission: "kubernetes_cluster.manage", after: after,
		payload: struct {
			NetworkID string           `json:"network_id"`
			SessionID string           `json:"session_id"`
			ClusterID string           `json:"cluster_id"`
			Name      string           `json:"name"`
			Authority catalogAuthority `json:"authority"`
		}{record.NetworkID, session.ID().String(), record.Cluster.ClusterID, record.Cluster.Name, record.Authority},
		outboxClass: action,
		outbox: struct {
			NetworkID string `json:"network_id"`
			ClusterID string `json:"cluster_id"`
			Version   int64  `json:"version"`
		}{record.NetworkID, record.Cluster.ClusterID, record.Cluster.Version},
	}
	if record.Before != nil {
		before, err := kubernetesSemanticHash(struct {
			NetworkID string `json:"network_id"`
			ClusterID string `json:"cluster_id"`
			Name      string `json:"name"`
			State     string `json:"state"`
		}{record.NetworkID, record.Before.ClusterID, record.Before.Name, record.Before.State})
		if err != nil {
			return kubecluster.ErrInvalid
		}
		event.before = &before
	}
	if err := appendNetworkMemberEvent(ctx, tx, event); err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	return nil
}

// ListClusters authorizes network.read and returns the active clusters.
func (store *KubernetesClusterStore) ListClusters(ctx context.Context, session accountsession.Session,
	scope network.Scope) ([]kubecluster.Cluster, error) {
	var clusters []kubecluster.Cluster
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, listKubernetesClustersSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(),
			kubecluster.MaximumClustersPerNetwork)...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var listing struct {
			NetworkID string                      `json:"network_id"`
			Clusters  []kubernetesClusterDocument `json:"clusters"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &listing); err != nil ||
			listing.NetworkID != scope.NetworkID().String() || listing.Clusters == nil ||
			len(listing.Clusters) > kubecluster.MaximumClustersPerNetwork {
			return false, kubecluster.ErrInvalid
		}
		clusters = make([]kubecluster.Cluster, 0, len(listing.Clusters))
		for _, document := range listing.Clusters {
			cluster, err := document.cluster()
			if err != nil {
				return false, err
			}
			clusters = append(clusters, cluster)
		}
		return false, nil
	})
	if err != nil {
		return nil, err
	}
	return clusters, nil
}

type kubernetesReplicaDocument struct {
	DeviceID  string    `json:"device_id"`
	Name      string    `json:"name"`
	Ordinal   int       `json:"ordinal"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
}

// ReadCluster authorizes network.read and returns one cluster; keys and
// requests only to callers who may manage or approve.
func (store *KubernetesClusterStore) ReadCluster(ctx context.Context, session accountsession.Session,
	scope network.Scope, id kubecluster.ID) (kubecluster.Detail, error) {
	var detail kubecluster.Detail
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, readKubernetesClusterSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), id.String(),
			kubecluster.MaximumListedKeys, kubecluster.MaximumListedRequests)...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var read struct {
			NetworkID string                             `json:"network_id"`
			Cluster   kubernetesClusterDocument          `json:"cluster"`
			Replicas  []kubernetesReplicaDocument        `json:"replicas"`
			Keys      []kubernetesJoinKeyDocument        `json:"keys"`
			Requests  []kubernetesReplicaRequestDocument `json:"requests"`
			// Schema 229: present exactly when keys and requests are.
			KeyWarnings *kubernetesKeyWarningsDocument `json:"key_warnings"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &read); err != nil ||
			read.NetworkID != scope.NetworkID().String() || read.Replicas == nil ||
			len(read.Replicas) > kubecluster.MaximumOrdinal+1 || len(read.Keys) > kubecluster.MaximumListedKeys ||
			len(read.Requests) > kubecluster.MaximumListedRequests ||
			(read.KeyWarnings == nil) != (read.Keys == nil) {
			return false, kubecluster.ErrInvalid
		}
		cluster, err := read.Cluster.cluster()
		if err != nil || cluster.ID() != id {
			return false, kubecluster.ErrInvalid
		}
		detail = kubecluster.Detail{Cluster: cluster, Replicas: make([]kubecluster.Replica, 0, len(read.Replicas))}
		for _, replica := range read.Replicas {
			deviceID, err := node.ParseID(replica.DeviceID)
			if err != nil || replica.Ordinal < 0 || replica.Ordinal > kubecluster.MaximumOrdinal {
				return false, kubecluster.ErrInvalid
			}
			detail.Replicas = append(detail.Replicas, kubecluster.Replica{
				DeviceID: deviceID, Name: replica.Name, Ordinal: replica.Ordinal, State: replica.State,
				CreatedAt: replica.CreatedAt.UTC(),
			})
		}
		if read.Keys != nil {
			detail.Keys = make([]kubecluster.JoinKey, 0, len(read.Keys))
			for _, document := range read.Keys {
				key, err := document.key()
				if err != nil {
					return false, err
				}
				detail.Keys = append(detail.Keys, key)
			}
		}
		if read.KeyWarnings != nil {
			warnings, err := read.KeyWarnings.warnings()
			if err != nil {
				return false, err
			}
			// Schema 233 keeps refused rotation tokens out of this read.
			for _, warning := range warnings.Devices {
				if warning.LastReason.TokenRefused() {
					return false, kubecluster.ErrInvalid
				}
			}
			detail.KeyWarnings = &warnings
		}
		if read.Requests != nil {
			detail.Requests = make([]kubecluster.ReplicaRequestView, 0, len(read.Requests))
			for _, document := range read.Requests {
				view, err := document.view()
				if err != nil {
					return false, err
				}
				detail.Requests = append(detail.Requests, view)
			}
		}
		return false, nil
	})
	return detail, err
}

type kubernetesKeyWarningsDocument struct {
	Devices []struct {
		DeviceID   string    `json:"device_id"`
		Hostname   string    `json:"hostname"`
		Count24h   int       `json:"count_24h"`
		Count7d    int       `json:"count_7d"`
		LastAt     time.Time `json:"last_at"`
		LastReason string    `json:"last_reason"`
		KeyState   string    `json:"key_state"`
	} `json:"devices"`
	Truncated bool `json:"truncated"`
}

// warnings validates the summary of a cluster's gateway key events.
func (document kubernetesKeyWarningsDocument) warnings() (kubecluster.KeyWarnings, error) {
	if document.Devices == nil || len(document.Devices) > kubecluster.MaximumKeyWarnings {
		return kubecluster.KeyWarnings{}, kubecluster.ErrInvalid
	}
	warnings := kubecluster.KeyWarnings{Truncated: document.Truncated,
		Devices: make([]kubecluster.KeyWarning, 0, len(document.Devices))}
	for _, entry := range document.Devices {
		deviceID, err := node.ParseID(entry.DeviceID)
		reason, state := kubecluster.KeyEventReason(entry.LastReason), kubecluster.ReportedKeyState(entry.KeyState)
		if err != nil || entry.Hostname == "" || len(entry.Hostname) > 253 || entry.Count24h < 0 ||
			entry.Count7d < 1 || entry.Count24h > entry.Count7d || entry.LastAt.IsZero() || !reason.IsKnown() ||
			!state.IsKnown() {
			return kubecluster.KeyWarnings{}, kubecluster.ErrInvalid
		}
		warnings.Devices = append(warnings.Devices, kubecluster.KeyWarning{
			DeviceID: deviceID, Hostname: entry.Hostname, Last24h: entry.Count24h, Last7Days: entry.Count7d,
			LastAt: entry.LastAt.UTC(), LastReason: reason, KeyState: state,
		})
	}
	return warnings, nil
}

type kubernetesJoinKeyRecord struct {
	NetworkID         string                     `json:"network_id"`
	NetworkRevision   int64                      `json:"network_revision"`
	ClusterID         string                     `json:"cluster_id"`
	Cluster           *kubernetesClusterDocument `json:"cluster"`
	Before            *kubernetesJoinKeyDocument `json:"before"`
	Key               kubernetesJoinKeyDocument  `json:"key"`
	CancelledRequests int64                      `json:"cancelled_requests"`
	Authority         catalogAuthority           `json:"authority"`
}

// IssueJoinKey authorizes kubernetes_cluster.manage, stores the digest of
// the new secret and records kubernetes_join_key.issued.
func (store *KubernetesClusterStore) IssueJoinKey(ctx context.Context, issue kubecluster.KeyIssue) (
	kubecluster.JoinKey, error) {
	if !issue.Token.IsValid() || !issue.KeyID.IsValid() {
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
		if err := tx.QueryRow(ctx, issueKubernetesJoinKeySQL, append(sessionQueryArguments(issue.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), issue.ClusterID.String(),
			issue.KeyID.String(), digest.KeyID().String(), digestBytes[:], fingerprint[:],
			int64(issue.Lifetime/time.Second), int64(issue.Uses), changeID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record kubernetesJoinKeyRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil || record.Cluster == nil ||
			record.NetworkID != scope.NetworkID().String() || record.NetworkRevision <= 0 {
			return false, kubecluster.ErrInvalid
		}
		decoded, err := record.Key.key()
		if err != nil || decoded.ID() != issue.KeyID || decoded.State() != kubecluster.KeyActive ||
			decoded.Uses() != issue.Uses || decoded.ExpiresAt().Sub(decoded.CreatedAt()) != issue.Lifetime ||
			record.Cluster.ClusterID != issue.ClusterID.String() {
			return false, kubecluster.ErrInvalid
		}
		key = decoded
		record.ClusterID = record.Cluster.ClusterID
		return true, store.appendKeyEvent(ctx, tx, issue.Session, issue.CorrelationID, changeID,
			"kubernetes_join_key.issued", record)
	})
	return key, err
}

// RevokeJoinKey authorizes kubernetes_cluster.manage, revokes the key,
// cancels its open requests and records kubernetes_join_key.revoked.
func (store *KubernetesClusterStore) RevokeJoinKey(ctx context.Context, revocation kubecluster.KeyRevocation) (
	kubecluster.JoinKey, error) {
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.JoinKey{}, kubecluster.ErrUnavailable
	}
	scope := revocation.Scope
	var key kubecluster.JoinKey
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, revokeKubernetesJoinKeySQL, append(sessionQueryArguments(revocation.Session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), revocation.ClusterID.String(),
			revocation.KeyID.String(), changeID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record kubernetesJoinKeyRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil || record.Before == nil ||
			record.NetworkID != scope.NetworkID().String() || record.NetworkRevision <= 0 ||
			record.ClusterID != revocation.ClusterID.String() {
			return false, kubecluster.ErrInvalid
		}
		decoded, err := record.Key.key()
		if err != nil || decoded.ID() != revocation.KeyID || decoded.State() != kubecluster.KeyRevoked {
			return false, kubecluster.ErrInvalid
		}
		key = decoded
		return true, store.appendKeyEvent(ctx, tx, revocation.Session, revocation.CorrelationID, changeID,
			"kubernetes_join_key.revoked", record)
	})
	return key, err
}

func (store *KubernetesClusterStore) appendKeyEvent(ctx context.Context, tx accountSessionTransaction,
	session accountsession.Session, correlationID, changeID publicid.ID, action string,
	record kubernetesJoinKeyRecord) error {
	keyID, err := enrollment.ParseCredentialID(record.Key.KeyID)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	hash := func(document kubernetesJoinKeyDocument) ([32]byte, error) {
		return kubernetesSemanticHash(struct {
			NetworkID string `json:"network_id"`
			ClusterID string `json:"cluster_id"`
			KeyID     string `json:"key_id"`
			State     string `json:"state"`
			ExpiresAt string `json:"expires_at"`
			Uses      int    `json:"uses"`
		}{record.NetworkID, record.ClusterID, document.KeyID, document.State,
			document.ExpiresAt.UTC().Format(time.RFC3339Nano), document.Uses})
	}
	after, err := hash(record.Key)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	event := catalogEvent{
		session: session, correlationID: correlationID, changeID: changeID,
		aggregateKind: "enrollment_credential", aggregateID: publicid.ID(keyID),
		version: record.Key.Version, networkVersion: record.NetworkRevision,
		action: action, permission: "kubernetes_cluster.manage", after: after,
		payload: struct {
			NetworkID         string           `json:"network_id"`
			SessionID         string           `json:"session_id"`
			ClusterID         string           `json:"cluster_id"`
			KeyID             string           `json:"key_id"`
			KeyExpiresAt      string           `json:"key_expires_at"`
			Uses              int              `json:"uses"`
			CancelledRequests int64            `json:"cancelled_requests,omitempty"`
			Authority         catalogAuthority `json:"authority"`
		}{record.NetworkID, session.ID().String(), record.ClusterID, record.Key.KeyID,
			record.Key.ExpiresAt.UTC().Format(time.RFC3339), record.Key.Uses, record.CancelledRequests,
			record.Authority},
		outboxClass: action,
		outbox: struct {
			NetworkID string `json:"network_id"`
			ClusterID string `json:"cluster_id"`
			KeyID     string `json:"key_id"`
			Version   int64  `json:"version"`
		}{record.NetworkID, record.ClusterID, record.Key.KeyID, record.Key.Version},
	}
	if record.Before != nil {
		before, err := hash(*record.Before)
		if err != nil {
			return kubecluster.ErrInvalid
		}
		event.before = &before
	}
	if err := appendNetworkMemberEvent(ctx, tx, event); err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	return nil
}

// kubernetesTrustSetDocument is the signing trust a cluster's first
// approval anchored (schema 232): it enters the approval's audit event.
type kubernetesTrustSetDocument struct {
	TrustID        string   `json:"trust_id"`
	Version        int64    `json:"version"`
	Issuer         string   `json:"issuer"`
	Namespace      string   `json:"namespace"`
	ServiceAccount string   `json:"service_account"`
	StatefulSet    string   `json:"statefulset"`
	KeyThumbprints []string `json:"key_thumbprints"`
}

type kubernetesRequestRecord struct {
	Outcome string `json:"outcome"`
	// TrustSet is what an approval anchored as the cluster's signing trust
	// (schema 232), null when the cluster had one.
	TrustSet        *kubernetesTrustSetDocument       `json:"trust_set,omitempty"`
	NetworkID       string                            `json:"network_id"`
	NetworkRevision int64                             `json:"network_revision"`
	Before          *kubernetesReplicaRequestDocument `json:"before"`
	Request         kubernetesReplicaRequestDocument  `json:"request"`
	Authority       catalogAuthority                  `json:"authority"`
}

// DecideReplicaRequest authorizes kubernetes_cluster.approve. An approval
// first locks the request and compares the code with the one computed from
// its keys and nonce, in constant time; a match approves (or, when the key
// is no longer usable, cancels), a mismatch counts a failure. A rejection
// rejects. Each outcome commits with its event before the result returns.
func (store *KubernetesClusterStore) DecideReplicaRequest(ctx context.Context, decision kubecluster.Decision) (
	kubecluster.ReplicaRequestView, error) {
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.ReplicaRequestView{}, kubecluster.ErrUnavailable
	}
	scope := decision.Scope
	var view kubecluster.ReplicaRequestView
	var outcome error
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		statement, action := rejectKubernetesReplicaRequestSQL, "kubernetes_replica_request.rejected"
		legacy := false
		if decision.Kind == kubecluster.DecisionApprove {
			matched, codeVersion, err := store.codeMatches(ctx, tx, decision, changeID)
			if err != nil {
				return false, err
			}
			// Schema 232: a request without trust is cancelled by the
			// approval, whatever the code.
			legacy = codeVersion == 1
			statement, action = approveKubernetesReplicaRequestSQL, "kubernetes_replica_request.approved"
			if !matched && !legacy {
				statement, action = recordKubernetesJoinCodeFailureSQL, "kubernetes_replica_request.code_failed"
			}
		} else if decision.Kind != kubecluster.DecisionReject {
			return false, kubecluster.ErrInvalid
		}
		arguments := append(sessionQueryArguments(decision.Session), scope.WorkspaceID().String(),
			scope.NetworkID().String(), decision.ClusterID.String(), decision.RequestID.String(), changeID.String())
		if statement == approveKubernetesReplicaRequestSQL {
			// The database checks the code again from the request's keys and
			// trust.
			bits, ok := decision.Code.Bits()
			if !ok {
				return false, kubecluster.ErrInvalid
			}
			arguments = append(arguments, int64(bits)) //nolint:gosec // G115: a code has 50 bits, below 2^63.
		}
		var encoded string
		if err := tx.QueryRow(ctx, statement, arguments...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		var record kubernetesRequestRecord
		if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil || record.Before == nil ||
			record.NetworkID != scope.NetworkID().String() || record.NetworkRevision <= 0 {
			return false, kubecluster.ErrInvalid
		}
		decoded, err := record.Request.view()
		if err != nil || decoded.ID() != decision.RequestID || decoded.ClusterID() != decision.ClusterID {
			return false, kubecluster.ErrInvalid
		}
		view = decoded
		state := decoded.Lifecycle().State()
		switch {
		case action == "kubernetes_replica_request.code_failed":
			outcome = &kubecluster.WrongCodeError{
				Remaining: kubecluster.MaximumCodeAttempts - decoded.Lifecycle().FailedAttempts(),
			}
			if state == kubecluster.RequestCancelled {
				action = "kubernetes_replica_request.cancelled"
			}
		case action == "kubernetes_replica_request.approved" && record.Outcome == "cancelled" && legacy:
			action, outcome = "kubernetes_replica_request.cancelled", kubecluster.ErrJoinAgain
		case action == "kubernetes_replica_request.approved" && record.Outcome == "cancelled":
			action, outcome = "kubernetes_replica_request.cancelled", kubecluster.ErrKeyNotUsable
		case action == "kubernetes_replica_request.approved" && state != kubecluster.RequestApproved,
			action == "kubernetes_replica_request.rejected" && state != kubecluster.RequestRejected:
			return false, kubecluster.ErrInvalid
		}
		return true, store.appendRequestEvent(ctx, tx, decision, changeID, action, record)
	})
	if err != nil {
		return kubecluster.ReplicaRequestView{}, err
	}
	return view, outcome
}

// codeMatches locks the request and compares the typed code with the code v2
// its keys and trust give, and returns the request's code version: 1 is a
// request without trust (before schema 232), which no code approves. A
// request that is no longer waiting stops here.
func (store *KubernetesClusterStore) codeMatches(ctx context.Context, tx accountSessionTransaction,
	decision kubecluster.Decision, changeID publicid.ID) (bool, int, error) {
	var encoded string
	if err := tx.QueryRow(ctx, lockKubernetesReplicaRequestSQL, append(sessionQueryArguments(decision.Session),
		decision.Scope.WorkspaceID().String(), decision.Scope.NetworkID().String(), decision.ClusterID.String(),
		decision.RequestID.String(), changeID.String())...).Scan(&encoded); err != nil {
		return false, 0, kubernetesClusterDatabaseError(err)
	}
	var locked struct {
		Request      kubernetesReplicaRequestDocument `json:"request"`
		MachineKey   string                           `json:"machine_key"`
		NodeKey      string                           `json:"node_key"`
		RequestNonce string                           `json:"request_nonce"`
		CodeVersion  int                              `json:"code_version"`
		TrustDigest  *string                          `json:"trust_digest"`
	}
	if err := decodeIdentityCatalogJSON([]byte(encoded), &locked); err != nil {
		return false, 0, kubecluster.ErrInvalid
	}
	if locked.Request.State != string(kubecluster.RequestPending) {
		return false, 0, kubecluster.ErrNotWaiting
	}
	clusterID, err := kubecluster.ParseID(locked.Request.ClusterID)
	if err != nil || clusterID != decision.ClusterID {
		return false, 0, kubecluster.ErrInvalid
	}
	inputs := kubejoin.Inputs{ClusterID: [16]byte(publicid.ID(clusterID))}
	for _, field := range []struct {
		hex  string
		into []byte
	}{{locked.MachineKey, inputs.MachineKey[:]}, {locked.NodeKey, inputs.NodeKey[:]},
		{locked.RequestNonce, inputs.RequestNonce[:]}} {
		decoded, err := hex.DecodeString(field.hex)
		if err != nil || len(decoded) != len(field.into) {
			return false, 0, kubecluster.ErrInvalid
		}
		copy(field.into, decoded)
	}
	switch {
	case locked.CodeVersion == 1 && locked.TrustDigest == nil:
		return false, 1, nil
	case locked.CodeVersion != 2 || locked.TrustDigest == nil:
		return false, 0, kubecluster.ErrInvalid
	}
	digest, err := hex.DecodeString(*locked.TrustDigest)
	if err != nil || len(digest) != 32 {
		return false, 0, kubecluster.ErrInvalid
	}
	expected, err := kubejoin.ComputeV2(inputs, [32]byte(digest))
	if err != nil {
		return false, 0, kubecluster.ErrInvalid
	}
	return expected.Equal(decision.Code), 2, nil
}

func (store *KubernetesClusterStore) appendRequestEvent(ctx context.Context, tx accountSessionTransaction,
	decision kubecluster.Decision, changeID publicid.ID, action string, record kubernetesRequestRecord) error {
	hash := func(document kubernetesReplicaRequestDocument) ([32]byte, error) {
		return kubernetesSemanticHash(struct {
			NetworkID string `json:"network_id"`
			RequestID string `json:"request_id"`
			State     string `json:"state"`
			Attempts  int    `json:"failed_code_attempts"`
		}{record.NetworkID, document.RequestID, document.State, document.FailedAttempts})
	}
	before, err := hash(*record.Before)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	after, err := hash(record.Request)
	if err != nil {
		return kubecluster.ErrInvalid
	}
	event := catalogEvent{
		session: decision.Session, correlationID: decision.CorrelationID, changeID: changeID,
		aggregateKind: "kubernetes_replica_request", aggregateID: publicid.ID(decision.RequestID),
		version: record.Request.Version, networkVersion: record.NetworkRevision,
		action: action, permission: "kubernetes_cluster.approve", before: &before, after: after,
		payload: struct {
			NetworkID          string                      `json:"network_id"`
			SessionID          string                      `json:"session_id"`
			ClusterID          string                      `json:"cluster_id"`
			RequestID          string                      `json:"request_id"`
			KeyID              string                      `json:"key_id"`
			MachineFingerprint string                      `json:"machine_key_fingerprint"`
			NodeFingerprint    string                      `json:"node_key_fingerprint"`
			State              string                      `json:"state"`
			FailedAttempts     int                         `json:"failed_code_attempts"`
			ReservedOrdinal    *int                        `json:"reserved_ordinal,omitempty"`
			TrustSet           *kubernetesTrustSetDocument `json:"signing_trust_set,omitempty"`
			Authority          catalogAuthority            `json:"authority"`
		}{record.NetworkID, decision.Session.ID().String(), record.Request.ClusterID, record.Request.RequestID,
			record.Request.KeyID, record.Request.MachineFingerprint, record.Request.NodeFingerprint,
			record.Request.State, record.Request.FailedAttempts, record.Request.ReservedOrdinal, record.TrustSet,
			record.Authority},
		outboxClass: action,
		outbox: struct {
			NetworkID string `json:"network_id"`
			ClusterID string `json:"cluster_id"`
			RequestID string `json:"request_id"`
			Version   int64  `json:"version"`
		}{record.NetworkID, record.Request.ClusterID, record.Request.RequestID, record.Request.Version},
	}
	if err := appendNetworkMemberEvent(ctx, tx, event); err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	return nil
}

const (
	resolveKubernetesJoinScopeSQL = `SELECT deployment_public_id::TEXT, workspace_public_id::TEXT,
 network_public_id::TEXT, recovery_epoch
FROM mesh_ops.resolve_kubernetes_join_scope_v1($1::UUID)`
	lockKubernetesJoinKeySQL = `SELECT digest_algorithm, digest_key_id, token_digest
FROM mesh_ops.lock_kubernetes_join_key_v1($1::UUID)`
	// Schema 232: the request holds the pod's verified trust.
	openKubernetesReplicaRequestSQL = `SELECT mesh_ops.open_kubernetes_replica_request_v2(
 $1::UUID,$2::UUID,$3::BYTEA,$4::BYTEA,$5::BYTEA,$6::BYTEA,$7::TEXT,$8::JSONB,$9::BYTEA,$10::UUID,
 $11::TEXT,$12::BYTEA,$13::BYTEA[],$14::TEXT,$15::TEXT,$16::TEXT,$17::TEXT,$18::BYTEA,$19::BYTEA)::TEXT`
)

var _ kubecluster.JoinStore = (*KubernetesClusterStore)(nil)

// OpenReplicaRequest resolves the join key's Network, locks the key,
// verifies the presented secret against its digest in constant time and
// opens (or returns) the replica's request, recording
// kubernetes_replica_request.opened with the key's issuer as actor. A key
// that is unknown, of another kind or whose secret differs returns
// ErrJoinRefused, never which.
func (store *KubernetesClusterStore) OpenReplicaRequest(ctx context.Context, attempt kubecluster.JoinAttempt) (
	kubecluster.JoinTicket, error) {
	if !attempt.IsValid() {
		return kubecluster.JoinTicket{}, kubecluster.ErrInvalid
	}
	scope, deploymentID, epoch, err := store.joinScope(ctx, attempt.Presentation.CredentialID())
	if err != nil {
		return kubecluster.JoinTicket{}, err
	}
	changeID, err := publicid.New()
	if err != nil {
		return kubecluster.JoinTicket{}, kubecluster.ErrUnavailable
	}
	var ticket kubecluster.JoinTicket
	err = store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var algorithm, keyID string
		var stored []byte
		if err := tx.QueryRow(ctx, lockKubernetesJoinKeySQL, attempt.Presentation.CredentialID().String()).Scan(
			&algorithm, &keyID, &stored); err != nil {
			if errors.Is(kubernetesClusterDatabaseError(err), kubecluster.ErrForbidden) {
				return false, kubecluster.ErrJoinRefused
			}
			return false, kubernetesClusterDatabaseError(err)
		}
		digestKeyID, err := enrollment.NewDigestKeyID(keyID)
		if err != nil || algorithm != enrollment.DigestAlgorithmHMACSHA256 || len(stored) != 32 {
			return false, kubecluster.ErrJoinRefused
		}
		digest, err := enrollment.NewCredentialDigest(digestKeyID, [32]byte(stored))
		if err != nil || !store.keyring.Verify(deploymentID, epoch, attempt.Presentation.Token(), digest) {
			return false, kubecluster.ErrJoinRefused
		}
		machine, nodeKey := attempt.MachineKey.Bytes(), attempt.NodeKey.Bytes()
		machineFingerprint, nodeFingerprint := attempt.MachineKey.Fingerprint(), attempt.NodeKey.Fingerprint()
		trust := attempt.Trust
		thumbprints := make([][]byte, 0, len(trust.KeyThumbprints()))
		for _, thumbprint := range trust.KeyThumbprints() {
			thumbprints = append(thumbprints, thumbprint[:])
		}
		joinKey, trustDigest := trust.JoinKeyThumbprint(), trust.Digest()
		var encoded string
		if err := tx.QueryRow(ctx, openKubernetesReplicaRequestSQL, attempt.Presentation.CredentialID().String(),
			attempt.RequestID.String(), machine[:], machineFingerprint[:], nodeKey[:], nodeFingerprint[:],
			attempt.Hostname.String(), string(attempt.Reported), attempt.Nonce[:], changeID.String(),
			trust.Issuer(), trust.JWKS(), thumbprints, trust.Namespace(), trust.ServiceAccount(), trust.StatefulSet(),
			trust.PodName(), joinKey[:], trustDigest[:]).Scan(&encoded); err != nil {
			return false, kubernetesJoinDatabaseError(err)
		}
		var opened struct {
			Created         bool                             `json:"created"`
			TrustConflict   bool                             `json:"trust_conflict"`
			IssuerID        string                           `json:"key_issuer_principal_id"`
			NetworkID       string                           `json:"network_id"`
			NetworkRevision int64                            `json:"network_revision"`
			Request         kubernetesReplicaRequestDocument `json:"request"`
			Nonce           string                           `json:"request_nonce"`
		}
		if err := decodeIdentityCatalogJSON([]byte(encoded), &opened); err != nil {
			return false, kubecluster.ErrInvalid
		}
		view, err := opened.Request.view()
		nonce, nonceErr := hex.DecodeString(opened.Nonce)
		if err != nil || nonceErr != nil || len(nonce) != 32 {
			return false, kubecluster.ErrInvalid
		}
		ticket = kubecluster.JoinTicket{Request: view, ClusterID: view.ClusterID(), Scope: scope,
			Nonce: [32]byte(nonce), Created: opened.Created, TrustConflict: opened.TrustConflict}
		if !opened.Created {
			return false, nil
		}
		if view.ID() != attempt.RequestID || ticket.Nonce != attempt.Nonce ||
			opened.NetworkID != scope.NetworkID().String() || opened.NetworkRevision <= 0 {
			return false, kubecluster.ErrInvalid
		}
		return true, store.appendOpenedEvent(ctx, tx, scope, changeID, opened.IssuerID, deploymentID.String(),
			opened.NetworkRevision, opened.Request)
	})
	if err != nil {
		return kubecluster.JoinTicket{}, err
	}
	return ticket, nil
}

// joinScope finds the Network of a join key; unknown keys are refused.
func (store *KubernetesClusterStore) joinScope(ctx context.Context, keyID enrollment.CredentialID) (
	network.Scope, deployment.ID, int64, error) {
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return network.Scope{}, deployment.ID{}, 0, errors.Join(kubecluster.ErrUnavailable, err)
	}
	defer func() { _ = rollbackAccountSessionTransaction(tx) }()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return network.Scope{}, deployment.ID{}, 0, errors.Join(kubecluster.ErrUnavailable, err)
	}
	var deploymentText, workspaceText, networkText string
	var epoch int64
	if err := tx.QueryRow(ctx, resolveKubernetesJoinScopeSQL, keyID.String()).Scan(
		&deploymentText, &workspaceText, &networkText, &epoch); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return network.Scope{}, deployment.ID{}, 0, kubecluster.ErrJoinRefused
		}
		return network.Scope{}, deployment.ID{}, 0, errors.Join(kubecluster.ErrUnavailable, err)
	}
	deploymentID, deploymentErr := deployment.ParseID(deploymentText)
	workspaceID, workspaceErr := workspace.ParseID(workspaceText)
	networkID, networkErr := network.ParseID(networkText)
	if deploymentErr != nil || workspaceErr != nil || networkErr != nil || epoch <= 0 {
		return network.Scope{}, deployment.ID{}, 0, kubecluster.ErrInvalid
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return network.Scope{}, deployment.ID{}, 0, kubecluster.ErrInvalid
	}
	return scope, deploymentID, epoch, nil
}

func kubernetesJoinDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "MTK03":
			return kubecluster.ErrQueueFull
		case "MTK06", "23505":
			return kubecluster.ErrKeysInUse
		case "MTK04":
			return kubecluster.ErrKeyNotUsable
		}
	}
	return kubernetesClusterDatabaseError(err)
}

func (store *KubernetesClusterStore) appendOpenedEvent(ctx context.Context, tx accountSessionTransaction,
	scope network.Scope, changeID publicid.ID, issuer, deploymentText string, networkRevision int64,
	request kubernetesReplicaRequestDocument) error {
	actor, err := publicid.Parse(issuer)
	requestID, requestErr := publicid.Parse(request.RequestID)
	if err != nil || requestErr != nil {
		return kubecluster.ErrInvalid
	}
	after, err := kubernetesSemanticHash(struct {
		NetworkID string `json:"network_id"`
		RequestID string `json:"request_id"`
		State     string `json:"state"`
		Attempts  int    `json:"failed_code_attempts"`
	}{scope.NetworkID().String(), request.RequestID, request.State, request.FailedAttempts})
	if err != nil {
		return kubecluster.ErrInvalid
	}
	event := catalogEvent{
		correlationID: changeID, changeID: changeID, aggregateKind: "kubernetes_replica_request",
		aggregateID: requestID, version: request.Version, networkVersion: networkRevision,
		action: "kubernetes_replica_request.opened", permission: "kubernetes_cluster.manage",
		after: after, actor: actor, deployment: deploymentText,
		payload: struct {
			NetworkID          string `json:"network_id"`
			ClusterID          string `json:"cluster_id"`
			RequestID          string `json:"request_id"`
			KeyID              string `json:"key_id"`
			MachineFingerprint string `json:"machine_key_fingerprint"`
			NodeFingerprint    string `json:"node_key_fingerprint"`
			Hostname           string `json:"hostname"`
		}{scope.NetworkID().String(), request.ClusterID, request.RequestID, request.KeyID,
			request.MachineFingerprint, request.NodeFingerprint, request.Hostname},
		outboxClass: "kubernetes_replica_request.opened",
		outbox: struct {
			NetworkID string `json:"network_id"`
			ClusterID string `json:"cluster_id"`
			RequestID string `json:"request_id"`
			Version   int64  `json:"version"`
		}{scope.NetworkID().String(), request.ClusterID, request.RequestID, request.Version},
	}
	if err := appendNetworkMemberEvent(ctx, tx, event); err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	return nil
}

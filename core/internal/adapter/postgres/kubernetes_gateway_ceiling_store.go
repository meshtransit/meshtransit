package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

var (
	// ErrInvalidKubernetesGatewayCeilingStore reports unsafe construction or
	// input.
	ErrInvalidKubernetesGatewayCeilingStore = errors.New("invalid postgres Kubernetes gateway ceiling store")
	// ErrKubernetesGatewayCeilingStore classifies a failed record.
	ErrKubernetesGatewayCeilingStore = errors.New("postgres Kubernetes gateway ceiling store")
)

// Schema 265 (K2h h4c): gateways' group ceilings.
const (
	recordKubernetesGatewayCeilingSQL = `SELECT mesh_ops.record_kubernetes_gateway_ceiling_v1(
    $1::BYTEA,$2::BYTEA,$3::JSONB,$4::BYTEA,$5::TIMESTAMPTZ,$6::TIMESTAMPTZ)`
	gatewayCeilingsGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(pg_catalog.to_regprocedure(
    'mesh_ops.record_kubernetes_gateway_ceiling_v1(bytea,bytea,jsonb,bytea,timestamp with time zone,timestamp with time zone)'),
    'EXECUTE'), FALSE)`
	listKubernetesCeilingsSQL = `SELECT mesh_ops.list_kubernetes_cluster_ceilings_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID)::TEXT`
	readKubernetesCeilingSQL = `SELECT mesh_ops.read_kubernetes_cluster_ceiling_v1(` + sessionArguments + `,
 $10::UUID,$11::UUID,$12::UUID,$13::BYTEA)::TEXT`
	// maximumStoredCeilingText bounds a body as PostgreSQL writes it out:
	// wider than Core's encoding (a space after each colon and comma), as
	// the table bounds it.
	maximumStoredCeilingText = 2 << 20
	// maximumCeilingListBytes bounds a list read: four bodies and the
	// replicas; maximumCeilingReadBytes one body and its hash.
	maximumCeilingListBytes = kubecluster.MaximumCeilingBodies*maximumStoredCeilingText + 64<<10
	maximumCeilingReadBytes = maximumStoredCeilingText + 1<<10
	// A ceiling decides nothing: it waits briefly for nothing.
	gatewayCeilingLockTimeout      = 500 * time.Millisecond
	gatewayCeilingStatementTimeout = 3 * time.Second
)

// GatewayCeilingOutcome is what recording a ceiling did.
type GatewayCeilingOutcome int

const (
	// GatewayCeilingStored kept the ceiling.
	GatewayCeilingStored GatewayCeilingOutcome = iota + 1
	// GatewayCeilingOlder found a newer ceiling kept.
	GatewayCeilingOlder
	// GatewayCeilingNotGateway found no gateway Device holding the keys.
	GatewayCeilingNotGateway
)

// KubernetesGatewayCeilingStore keeps each gateway Device's latest ceiling,
// through the runtime pool of the control plane (schema 265).
type KubernetesGatewayCeilingStore struct{ database outboxDatabase }

// NewKubernetesGatewayCeilingStore accepts the runtime pool only.
func NewKubernetesGatewayCeilingStore(pool *Pool) (*KubernetesGatewayCeilingStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.outboxDatabase == nil {
		return nil, ErrInvalidKubernetesGatewayCeilingStore
	}
	return &KubernetesGatewayCeilingStore{database: pool.outboxDatabase}, nil
}

// Granted reports whether the runtime role may record ceilings (schema 265).
func (store *KubernetesGatewayCeilingStore) Granted(ctx context.Context) (bool, error) {
	if ctx == nil || store == nil || store.database == nil {
		return false, ErrInvalidKubernetesGatewayCeilingStore
	}
	var granted bool
	if err := store.database.QueryRow(ctx, gatewayCeilingsGrantedSQL).Scan(&granted); err != nil {
		return false, errors.Join(ErrKubernetesGatewayCeilingStore, err)
	}
	return granted, nil
}

// Record keeps ceiling for the gateway Device holding machine (its
// node-domain fingerprint) and nodeKey now; it hashes Core's own encoding.
func (store *KubernetesGatewayCeilingStore) Record(ctx context.Context, machine [32]byte, nodeKey []byte,
	ceiling kubecluster.EncodedCeiling) (outcome GatewayCeilingOutcome, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || machine == ([32]byte{}) || len(nodeKey) != 32 ||
		ceiling.IsZero() {
		return 0, ErrInvalidKubernetesGatewayCeilingStore
	}
	hash := ceiling.Hash()
	var checkedAt any
	if !ceiling.CheckedAt().IsZero() {
		checkedAt = ceiling.CheckedAt().UTC()
	}
	transaction, err := store.database.Begin(ctx, false)
	if err != nil || transaction == nil {
		return 0, errors.Join(ErrKubernetesGatewayCeilingStore, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
		}
	}()
	statement := postgresTimeout(gatewayCeilingStatementTimeout)
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, statement,
		postgresTimeout(gatewayCeilingLockTimeout), statement); err != nil {
		return 0, errors.Join(ErrKubernetesGatewayCeilingStore, err)
	}
	var result string
	if err := transaction.QueryRow(ctx, recordKubernetesGatewayCeilingSQL, machine[:], nodeKey,
		string(ceiling.Bytes()), hash[:], checkedAt, ceiling.ReceivedAt().UTC()).Scan(&result); err != nil {
		return 0, errors.Join(ErrKubernetesGatewayCeilingStore, err)
	}
	switch result {
	case "unknown":
		return GatewayCeilingNotGateway, nil
	case "older", "stored":
	default:
		return 0, ErrKubernetesGatewayCeilingStore
	}
	if err := transaction.Commit(ctx); err != nil {
		committed = true
		return 0, errors.Join(ErrKubernetesGatewayCeilingStore, err)
	}
	committed = true
	if result == "older" {
		return GatewayCeilingOlder, nil
	}
	return GatewayCeilingStored, nil
}

type kubernetesCeilingDocument struct {
	ContentHash string          `json:"content_hash"`
	Body        json.RawMessage `json:"body"`
}

// document checks a stored ceiling: its body re-encodes to its hash. A
// row that does not is damaged, not the reader's mistake: unavailable
// (review h4c M1).
func (document kubernetesCeilingDocument) document() (kubecluster.CeilingDocument, error) {
	var body kubecluster.CeilingBody
	if err := decodeStrictJSON(string(document.Body), maximumStoredCeilingText, &body); err != nil {
		return kubecluster.CeilingDocument{}, kubecluster.ErrUnavailable
	}
	_, hash, err := body.Encode()
	if err != nil || hex.EncodeToString(hash[:]) != document.ContentHash {
		return kubecluster.CeilingDocument{}, kubecluster.ErrUnavailable
	}
	return kubecluster.CeilingDocument{ContentHash: document.ContentHash, Body: body}, nil
}

// ListGroupCeilings reads a cluster's active replicas with their latest
// ceilings and at most four distinct bodies.
func (store *KubernetesClusterStore) ListGroupCeilings(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID) (kubecluster.ClusterCeilings, error) {
	var read struct {
		Replicas []struct {
			DeviceID    string     `json:"device_id"`
			ReceivedAt  *time.Time `json:"received_at"`
			CheckedAt   *time.Time `json:"checked_at"`
			ContentHash *string    `json:"content_hash"`
		} `json:"replicas"`
		Bodies []kubernetesCeilingDocument `json:"bodies"`
	}
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		var encoded string
		if err := tx.QueryRow(ctx, listKubernetesCeilingsSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), clusterID.String())...).Scan(&encoded); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		// What the database wrote cannot be the reader's mistake (review h4c M1).
		if err := decodeStrictJSON(encoded, maximumCeilingListBytes, &read); err != nil {
			return false, kubecluster.ErrUnavailable
		}
		return false, nil
	})
	if err != nil {
		return kubecluster.ClusterCeilings{}, err
	}
	if read.Replicas == nil || read.Bodies == nil || len(read.Bodies) > kubecluster.MaximumCeilingBodies {
		return kubecluster.ClusterCeilings{}, kubecluster.ErrUnavailable
	}
	ceilings := kubecluster.ClusterCeilings{
		Replicas: make([]kubecluster.ReplicaCeiling, 0, len(read.Replicas)),
		Bodies:   make([]kubecluster.CeilingDocument, 0, len(read.Bodies)),
	}
	for _, replica := range read.Replicas {
		deviceID, err := node.ParseID(replica.DeviceID)
		if err != nil || (replica.ContentHash == nil) != (replica.ReceivedAt == nil) {
			return kubecluster.ClusterCeilings{}, kubecluster.ErrUnavailable
		}
		held := kubecluster.ReplicaCeiling{DeviceID: deviceID}
		if replica.ContentHash != nil {
			if decoded, err := hex.DecodeString(*replica.ContentHash); err != nil || len(decoded) != 32 {
				return kubecluster.ClusterCeilings{}, kubecluster.ErrUnavailable
			}
			held.ContentHash, held.ReceivedAt = *replica.ContentHash, replica.ReceivedAt.UTC()
			if replica.CheckedAt != nil {
				held.CheckedAt = replica.CheckedAt.UTC()
			}
		}
		ceilings.Replicas = append(ceilings.Replicas, held)
	}
	// A damaged body is left out, its hash kept on its replicas: the rest
	// still reads, and reading that hash alone answers unavailable.
	for _, body := range read.Bodies {
		if document, err := body.document(); err == nil {
			ceilings.Bodies = append(ceilings.Bodies, document)
		}
	}
	return ceilings, nil
}

// ReadGroupCeiling reads one of a cluster's ceilings by its hash.
func (store *KubernetesClusterStore) ReadGroupCeiling(ctx context.Context, session accountsession.Session,
	scope network.Scope, clusterID kubecluster.ID, contentHash [32]byte) (kubecluster.CeilingDocument, error) {
	var read *string
	err := store.transact(ctx, scope, func(tx accountSessionTransaction) (bool, error) {
		if err := tx.QueryRow(ctx, readKubernetesCeilingSQL, append(sessionQueryArguments(session),
			scope.WorkspaceID().String(), scope.NetworkID().String(), clusterID.String(),
			contentHash[:])...).Scan(&read); err != nil {
			return false, kubernetesClusterDatabaseError(err)
		}
		return false, nil
	})
	if err != nil {
		return kubecluster.CeilingDocument{}, err
	}
	if read == nil {
		return kubecluster.CeilingDocument{}, kubecluster.ErrNotFound
	}
	var document kubernetesCeilingDocument
	if err := decodeStrictJSON(*read, maximumCeilingReadBytes, &document); err != nil {
		return kubecluster.CeilingDocument{}, kubecluster.ErrUnavailable
	}
	found, err := document.document()
	if err != nil || found.ContentHash != hex.EncodeToString(contentHash[:]) {
		return kubecluster.CeilingDocument{}, kubecluster.ErrUnavailable
	}
	return found, nil
}

package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

var (
	// ErrInvalidKubernetesClusterCAStore reports unsafe construction or
	// input.
	ErrInvalidKubernetesClusterCAStore = errors.New("invalid postgres Kubernetes cluster CA store")
	// ErrKubernetesClusterCAStore classifies a failed read or change.
	ErrKubernetesClusterCAStore = errors.New("postgres Kubernetes cluster CA store")
	// ErrKubernetesClusterCAStale reports a move of a CA that changed since
	// it was read; nothing of the change was applied.
	ErrKubernetesClusterCAStale = errors.New("postgres Kubernetes cluster CA changed since it was read")
	// ErrKubernetesClusterCABusy reports a Network another worker holds.
	ErrKubernetesClusterCABusy = errors.New("postgres Kubernetes cluster CA Network is busy")
)

const (
	listKubernetesCAWorkSQL    = `SELECT mesh_ops.read_kubernetes_ca_work_v1($1::UUID,$2::INTEGER)::TEXT`
	lockKubernetesCANetworkSQL = `SELECT mesh_ops.lock_kubernetes_ca_network_v1($1::UUID,$2::UUID,$3::UUID)::TEXT`
	addKubernetesCADataKeySQL  = `SELECT mesh_ops.add_kubernetes_ca_data_key_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::TEXT,$6::TEXT,$7::BYTEA)::TEXT`
	createKubernetesClusterCASQL = `SELECT mesh_ops.create_kubernetes_cluster_ca_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::UUID,$6::UUID,$7::TEXT,$8::TEXT,$9::UUID,$10::BYTEA,$11::TEXT,
    $12::TIMESTAMPTZ,$13::TIMESTAMPTZ,$14::BYTEA)::TEXT`
	moveKubernetesClusterCASQL = `SELECT mesh_ops.move_kubernetes_cluster_ca_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::UUID,$6::BIGINT,$7::TEXT,$8::TEXT)::TEXT`
	appendKubernetesClusterCAEvidenceSQL = `SELECT mesh_ops.append_kubernetes_cluster_ca_evidence_v1(
    $1::UUID,$2::BIGINT,$3::BIGINT,$4::BYTEA,$5::BYTEA,$6::UUID,$7::UUID,$8::JSONB,$9::BIGINT)`
	scheduleKubernetesClusterCASQL = `SELECT mesh_ops.schedule_kubernetes_cluster_ca_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::TIMESTAMPTZ,$6::BOOLEAN)::TEXT`
	postponeKubernetesCANetworkSQL = `SELECT mesh_ops.postpone_kubernetes_ca_network_v1(
    $1::UUID,$2::UUID,$3::UUID,$4::TIMESTAMPTZ)::TEXT`
	beatKubernetesCAWorkerSQL = `SELECT mesh_ops.beat_kubernetes_ca_worker_v1($1::UUID,$2::UUID,$3::BOOLEAN,$4::TEXT,$5::TEXT)`

	clusterCAAggregateKind = "kubernetes_cluster_ca"
	clusterCAMaximumDue    = 256
	// The read holds at most 96 clusters, each with at most three live
	// CAs of at most 8 KiB, hex encoded.
	clusterCAMaximumNetwork = 8 << 20
	clusterCAMaximumPayload = 4096
	clusterCAMaximumSteps   = 512
	// The plan runs inside the transaction and holds the Network's lock:
	// generating and sealing CAs takes milliseconds, and a data key it
	// must unwrap through the custody is bounded by the custody's own
	// timeout, well under the idle limit.
	clusterCAStatementTimeout = 10 * time.Second
	clusterCALockTimeout      = 2 * time.Second
	clusterCAIdleTimeout      = 30 * time.Second
)

// KubernetesClusterCAStore keeps the CAs of Kubernetes clusters for the
// worker (schema 238): what is due, the Networks' data keys, CA changes
// under each Network's lock with their sealed audit events, schedules and
// heartbeats. It never sees a key in the clear.
type KubernetesClusterCAStore struct{ database outboxDatabase }

// NewKubernetesClusterCAStore accepts the worker pool only.
func NewKubernetesClusterCAStore(pool *Pool) (*KubernetesClusterCAStore, error) {
	if pool == nil || pool.role != PoolRoleWorker || pool.outboxDatabase == nil {
		return nil, ErrInvalidKubernetesClusterCAStore
	}
	return &KubernetesClusterCAStore{database: pool.outboxDatabase}, nil
}

func (store *KubernetesClusterCAStore) valid(ctx context.Context, installation deployment.ID) bool {
	return ctx != nil && store != nil && store.database != nil && installation.IsValid()
}

func (store *KubernetesClusterCAStore) begin(ctx context.Context) (outboxTransaction, error) {
	transaction, err := store.database.Begin(ctx, false)
	if err != nil || transaction == nil {
		return nil, errors.Join(ErrKubernetesClusterCAStore, err)
	}
	if err := transaction.Exec(ctx, configureAuthTransactionSQL, postgresTimeout(clusterCAStatementTimeout),
		postgresTimeout(clusterCALockTimeout), postgresTimeout(clusterCAIdleTimeout)); err != nil {
		return nil, errors.Join(ErrKubernetesClusterCAStore, err, rollbackOutboxTransaction(transaction))
	}
	return transaction, nil
}

// inTransaction runs work in one transaction and commits it unless work
// fails or says not to.
func (store *KubernetesClusterCAStore) inTransaction(ctx context.Context,
	work func(outboxTransaction) (bool, error),
) (resultErr error) {
	transaction, err := store.begin(ctx)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackOutboxTransaction(transaction))
		}
	}()
	commit, err := work(transaction)
	if err != nil || !commit {
		return err
	}
	committed = true
	if err := transaction.Commit(ctx); err != nil {
		return errors.Join(ErrKubernetesClusterCAStore, err)
	}
	return nil
}

// ListDue lists the installation's Networks with a cluster due, earliest
// first.
func (store *KubernetesClusterCAStore) ListDue(ctx context.Context, installation deployment.ID,
	limit int,
) ([]network.Scope, error) {
	if !store.valid(ctx, installation) || limit < 1 || limit > clusterCAMaximumDue {
		return nil, ErrInvalidKubernetesClusterCAStore
	}
	var scopes []network.Scope
	err := store.inTransaction(ctx, func(transaction outboxTransaction) (bool, error) {
		var encoded string
		if err := transaction.QueryRow(ctx, listKubernetesCAWorkSQL, installation.String(), limit).
			Scan(&encoded); err != nil {
			return false, errors.Join(ErrKubernetesClusterCAStore, err)
		}
		var record struct {
			Now      time.Time `json:"now"`
			Networks []struct {
				WorkspaceID string `json:"workspace_id"`
				NetworkID   string `json:"network_id"`
			} `json:"networks"`
		}
		if err := decodeStrictJSON(encoded, 65536, &record); err != nil || record.Networks == nil ||
			len(record.Networks) > limit {
			return false, ErrKubernetesClusterCAStore
		}
		scopes = make([]network.Scope, 0, len(record.Networks))
		for _, item := range record.Networks {
			scope, err := parseClusterCAScope(item.WorkspaceID, item.NetworkID)
			if err != nil {
				return false, err
			}
			scopes = append(scopes, scope)
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return scopes, nil
}

func parseClusterCAScope(workspaceText, networkText string) (network.Scope, error) {
	workspaceID, workspaceErr := workspace.ParseID(workspaceText)
	networkID, networkErr := network.ParseID(networkText)
	scope, scopeErr := network.NewScope(workspaceID, networkID)
	if workspaceErr != nil || networkErr != nil || scopeErr != nil {
		return network.Scope{}, ErrKubernetesClusterCAStore
	}
	return scope, nil
}

// AddDataKey stores the Network's first data key, wrapped by the custody,
// unless another worker stored one first, and returns the active key
// either way.
func (store *KubernetesClusterCAStore) AddDataKey(ctx context.Context, installation deployment.ID,
	scope network.Scope, id publicid.ID, wrapped kubeca.WrappedKey,
) (kubeca.StoredDataKey, error) {
	if !store.valid(ctx, installation) || !scope.IsValid() || !id.IsValid() || wrapped.Custody == "" ||
		wrapped.KeyID == "" || len(wrapped.Ciphertext) == 0 {
		return kubeca.StoredDataKey{}, ErrInvalidKubernetesClusterCAStore
	}
	var stored kubeca.StoredDataKey
	err := store.inTransaction(ctx, func(transaction outboxTransaction) (bool, error) {
		var encoded string
		if err := transaction.QueryRow(ctx, addKubernetesCADataKeySQL, installation.String(),
			scope.WorkspaceID().String(), scope.NetworkID().String(), id.String(), wrapped.Custody, wrapped.KeyID,
			wrapped.Ciphertext).Scan(&encoded); err != nil {
			return false, errors.Join(ErrKubernetesClusterCAStore, err)
		}
		var record struct {
			Outcome    string `json:"outcome"`
			ID         string `json:"id"`
			Custody    string `json:"custody"`
			KeyID      string `json:"key_id"`
			Ciphertext string `json:"ciphertext"`
		}
		if err := decodeStrictJSON(encoded, 16384, &record); err != nil {
			return false, ErrKubernetesClusterCAStore
		}
		if record.Outcome == "busy" {
			return false, ErrKubernetesClusterCABusy
		}
		key, err := decodeClusterCADataKey(clusterCADataKeyRecord{
			ID: record.ID, Custody: record.Custody,
			KeyID: record.KeyID, Ciphertext: record.Ciphertext, Active: true,
		})
		if err != nil || record.Outcome != "added" && record.Outcome != "existing" ||
			(record.Outcome == "added") != (key.ID == id) {
			return false, ErrKubernetesClusterCAStore
		}
		stored = key
		return true, nil
	})
	return stored, err
}

// Change reads the Network under its CA lock, asks plan what to change and
// applies it in the same transaction: each step its own change with its
// sealed audit event, then the schedules. busy is true, and plan is not
// called, when another worker holds the Network. A plan error, a refused
// step or a stale move applies nothing.
func (store *KubernetesClusterCAStore) Change(ctx context.Context, installation deployment.ID, scope network.Scope,
	plan func(kubeca.Network) (kubeca.Changes, error),
) (bool, error) {
	if !store.valid(ctx, installation) || !scope.IsValid() || plan == nil {
		return false, ErrInvalidKubernetesClusterCAStore
	}
	// Another writer that moves the Network's revision or audit stream
	// between a step's proof and its evidence fails the change with 40001:
	// it is redone whole, the plan included, within a bounded budget.
	return retryReadConflict(ctx, func() (bool, error) {
		return store.changeOnce(ctx, installation, scope, plan)
	})
}

func (store *KubernetesClusterCAStore) changeOnce(ctx context.Context, installation deployment.ID,
	scope network.Scope, plan func(kubeca.Network) (kubeca.Changes, error),
) (busy bool, resultErr error) {
	err := store.inTransaction(ctx, func(transaction outboxTransaction) (bool, error) {
		var encoded string
		if err := transaction.QueryRow(ctx, lockKubernetesCANetworkSQL, installation.String(),
			scope.WorkspaceID().String(), scope.NetworkID().String()).Scan(&encoded); err != nil {
			return false, errors.Join(ErrKubernetesClusterCAStore, err)
		}
		read, locked, err := decodeClusterCANetwork(encoded)
		if err != nil || !locked {
			busy = err == nil
			return false, err
		}
		changes, err := plan(read)
		if err != nil {
			return false, err
		}
		if len(changes.Steps)+len(changes.Schedules) > clusterCAMaximumSteps {
			return false, ErrInvalidKubernetesClusterCAStore
		}
		apply := clusterCAChange{ctx: ctx, transaction: transaction, installation: installation, scope: scope}
		for _, step := range changes.Steps {
			if err := apply.step(step); err != nil {
				return false, err
			}
		}
		for _, schedule := range changes.Schedules {
			if err := apply.schedule(schedule); err != nil {
				return false, err
			}
		}
		return true, nil
	})
	if errors.Is(err, ErrKubernetesClusterCABusy) {
		return true, nil
	}
	return busy, err
}

// Postpone puts off a Network's due clusters after a failed look, counting
// the failure, without reading them: a Network the worker cannot read or
// plan does not stay first in line. busy is true when another worker
// holds the Network.
func (store *KubernetesClusterCAStore) Postpone(ctx context.Context, installation deployment.ID,
	scope network.Scope, until time.Time,
) (bool, error) {
	if !store.valid(ctx, installation) || !scope.IsValid() || until.IsZero() {
		return false, ErrInvalidKubernetesClusterCAStore
	}
	busy := false
	err := store.inTransaction(ctx, func(transaction outboxTransaction) (bool, error) {
		var encoded string
		if err := transaction.QueryRow(ctx, postponeKubernetesCANetworkSQL, installation.String(),
			scope.WorkspaceID().String(), scope.NetworkID().String(), until).Scan(&encoded); err != nil {
			return false, errors.Join(ErrKubernetesClusterCAStore, err)
		}
		var record struct {
			Outcome  string `json:"outcome"`
			Clusters *int   `json:"clusters"`
		}
		if err := decodeStrictJSON(encoded, 1024, &record); err != nil {
			return false, ErrKubernetesClusterCAStore
		}
		switch {
		case record.Outcome == "busy" && record.Clusters == nil:
			busy = true
			return false, nil
		case record.Outcome == "postponed" && record.Clusters != nil && *record.Clusters >= 0:
			return true, nil
		}
		return false, ErrKubernetesClusterCAStore
	})
	return busy, err
}

// Beat records whether this worker process can sign and returns until when
// control may count on it.
func (store *KubernetesClusterCAStore) Beat(ctx context.Context, installation deployment.ID, instance publicid.ID,
	ready bool, version, custody string,
) (time.Time, error) {
	if !store.valid(ctx, installation) || !instance.IsValid() || version == "" || custody == "" {
		return time.Time{}, ErrInvalidKubernetesClusterCAStore
	}
	var readyUntil time.Time
	err := store.inTransaction(ctx, func(transaction outboxTransaction) (bool, error) {
		if err := transaction.QueryRow(ctx, beatKubernetesCAWorkerSQL, installation.String(), instance.String(), ready,
			version, custody).Scan(&readyUntil); err != nil {
			return false, errors.Join(ErrKubernetesClusterCAStore, err)
		}
		return true, nil
	})
	return readyUntil, err
}

// clusterCAChange applies one Network's steps in its transaction.
type clusterCAChange struct {
	ctx          context.Context
	transaction  outboxTransaction
	installation deployment.ID
	scope        network.Scope
}

func (apply clusterCAChange) step(step kubeca.Step) error {
	if (step.Create == nil) == (step.Move == nil) {
		return ErrInvalidKubernetesClusterCAStore
	}
	change, err := freshPublicID()
	if err != nil {
		return errors.Join(ErrKubernetesClusterCAStore, err)
	}
	var encoded string
	var ca publicid.ID
	if creation := step.Create; creation != nil {
		if !creation.Cluster.IsValid() || !creation.ID.IsValid() || !creation.DataKeyID.IsValid() ||
			creation.State != kubeca.StateActive && creation.State != kubeca.StateNext || !creation.Reason.CreatesCA() ||
			len(creation.Certificate) == 0 || len(creation.SealedKey) == 0 ||
			!kubeca.ValidDNSName(creation.ClusterDNSName) || !creation.NotAfter.After(creation.NotBefore) {
			return ErrInvalidKubernetesClusterCAStore
		}
		ca = creation.ID
		err = apply.transaction.QueryRow(apply.ctx, createKubernetesClusterCASQL, apply.installation.String(),
			apply.scope.WorkspaceID().String(), apply.scope.NetworkID().String(), creation.Cluster.String(),
			creation.ID.String(), change.String(), string(creation.State), string(creation.Reason),
			creation.DataKeyID.String(), creation.Certificate, creation.ClusterDNSName, creation.NotBefore,
			creation.NotAfter, creation.SealedKey).Scan(&encoded)
	} else {
		move := step.Move
		if !move.CA.IsValid() || move.Version < 1 || !move.Reason.MovesCA() ||
			move.To != kubeca.StateActive && move.To != kubeca.StateRetiring && move.To != kubeca.StateRetired {
			return ErrInvalidKubernetesClusterCAStore
		}
		ca = move.CA
		err = apply.transaction.QueryRow(apply.ctx, moveKubernetesClusterCASQL, apply.installation.String(),
			apply.scope.WorkspaceID().String(), apply.scope.NetworkID().String(), move.CA.String(), change.String(),
			move.Version, string(move.To), string(move.Reason)).Scan(&encoded)
	}
	if err != nil {
		return errors.Join(ErrKubernetesClusterCAStore, err)
	}
	proof, err := decodeClusterCAProof(encoded, ca)
	if err != nil {
		return err
	}
	return apply.evidence(proof, change)
}

// evidence appends the sealed audit event of the change the last step
// made.
func (apply clusterCAChange) evidence(proof clusterCAProof, change publicid.ID) error {
	auditEvent, auditErr := freshPublicID()
	outbox, outboxErr := freshPublicID()
	if auditErr != nil || outboxErr != nil {
		return errors.Join(ErrKubernetesClusterCAStore, auditErr, outboxErr)
	}
	hash, previous, err := hashClusterCAEvent(proof, change, auditEvent)
	if err != nil {
		return err
	}
	var sequence int64
	if err := apply.transaction.QueryRow(apply.ctx, appendKubernetesClusterCAEvidenceSQL, proof.CAID,
		proof.StreamID, proof.Sequence, previous, hash[:], auditEvent.String(), outbox.String(), proof.Payload,
		proof.NetworkRevision).Scan(&sequence); err != nil {
		return errors.Join(ErrKubernetesClusterCAStore, err)
	}
	if sequence != proof.Sequence {
		return ErrKubernetesClusterCAStore
	}
	return nil
}

func (apply clusterCAChange) schedule(schedule kubeca.Schedule) error {
	if !schedule.Cluster.IsValid() || schedule.Done && (schedule.Failed || !schedule.At.IsZero()) ||
		!schedule.Done && schedule.At.IsZero() {
		return ErrInvalidKubernetesClusterCAStore
	}
	var at any
	if !schedule.Done {
		at = schedule.At
	}
	var encoded string
	if err := apply.transaction.QueryRow(apply.ctx, scheduleKubernetesClusterCASQL, apply.installation.String(),
		apply.scope.WorkspaceID().String(), apply.scope.NetworkID().String(), schedule.Cluster.String(), at,
		schedule.Failed).Scan(&encoded); err != nil {
		return errors.Join(ErrKubernetesClusterCAStore, err)
	}
	var record struct {
		Outcome      string     `json:"outcome"`
		NextActionAt *time.Time `json:"next_action_at"`
	}
	if err := decodeStrictJSON(encoded, 1024, &record); err != nil {
		return ErrKubernetesClusterCAStore
	}
	switch {
	case record.Outcome == "busy":
		return ErrKubernetesClusterCABusy
	case schedule.Done && record.Outcome == "done" && record.NextActionAt == nil,
		!schedule.Done && record.Outcome == "scheduled" && record.NextActionAt != nil:
		return nil
	}
	return ErrKubernetesClusterCAStore
}

// clusterCAProof is the head of the Network's audit stream and the payload
// of the CA row a step changed.
type clusterCAProof struct {
	Outcome         string `json:"outcome"`
	Action          string `json:"action"`
	CAID            string `json:"ca_id"`
	Version         int64  `json:"version"`
	NetworkRevision int64  `json:"network_revision"`
	SemanticHash    string `json:"semantic_hash"`
	StreamID        int64  `json:"stream_id"`
	Sequence        int64  `json:"sequence"`
	PreviousHash    string `json:"previous_hash"`
	Payload         string `json:"payload"`
}

func decodeClusterCAProof(encoded string, ca publicid.ID) (clusterCAProof, error) {
	var proof clusterCAProof
	if err := decodeStrictJSON(encoded, 16384, &proof); err != nil {
		return clusterCAProof{}, ErrKubernetesClusterCAStore
	}
	switch proof.Outcome {
	case "busy", "stale":
		if proof != (clusterCAProof{Outcome: proof.Outcome}) {
			return clusterCAProof{}, ErrKubernetesClusterCAStore
		}
		if proof.Outcome == "busy" {
			return clusterCAProof{}, ErrKubernetesClusterCABusy
		}
		return clusterCAProof{}, ErrKubernetesClusterCAStale
	case "changed":
	default:
		return clusterCAProof{}, ErrKubernetesClusterCAStore
	}
	semantic, semanticErr := hex.DecodeString(proof.SemanticHash)
	previous, previousErr := hex.DecodeString(proof.PreviousHash)
	payloadHash := sha256.Sum256([]byte(proof.Payload))
	switch proof.Action {
	case "kubernetes_cluster.ca_created", "kubernetes_cluster.ca_activated", "kubernetes_cluster.ca_retiring",
		"kubernetes_cluster.ca_retired":
	default:
		return clusterCAProof{}, ErrKubernetesClusterCAStore
	}
	if proof.CAID != ca.String() || proof.Version < 1 || proof.NetworkRevision < 1 || semanticErr != nil ||
		len(semantic) != sha256.Size || previousErr != nil || len(previous) != sha256.Size || proof.StreamID < 1 ||
		proof.Sequence < 1 || len(proof.Payload) == 0 || len(proof.Payload) > clusterCAMaximumPayload ||
		!json.Valid([]byte(proof.Payload)) || [sha256.Size]byte(semantic) != payloadHash {
		return clusterCAProof{}, ErrKubernetesClusterCAStore
	}
	return proof, nil
}

// hashClusterCAEvent binds the event to the stream head the database
// returned, as for gateway key events: a system change, no actor or
// correlation, the payload's semantic hash.
func hashClusterCAEvent(proof clusterCAProof, change, event publicid.ID) ([sha256.Size]byte, []byte, error) {
	previous, err := hex.DecodeString(proof.PreviousHash)
	if err != nil || len(previous) != sha256.Size {
		return [sha256.Size]byte{}, nil, ErrKubernetesClusterCAStore
	}
	aggregate, err := publicid.Parse(proof.CAID)
	if err != nil {
		return [sha256.Size]byte{}, nil, ErrKubernetesClusterCAStore
	}
	payloadHash := sha256.Sum256([]byte(proof.Payload))
	hash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: [sha256.Size]byte(previous), EventID: event, ChangeID: change,
		AggregateKind: clusterCAAggregateKind, AggregateID: aggregate, AggregateVersion: proof.Version,
		NetworkRevision: proof.NetworkRevision, Action: proof.Action, Permission: enforcementLedgerPermission,
		AfterSemanticHash: payloadHash, AuditPayloadHash: payloadHash,
		OutboxEventClass: proof.Action, OutboxPayloadHash: payloadHash,
	})
	if err != nil {
		return [sha256.Size]byte{}, nil, errors.Join(ErrKubernetesClusterCAStore, err)
	}
	return hash, previous, nil
}

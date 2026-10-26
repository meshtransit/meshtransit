package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	setKubernetesCompletionScopeSQL = `SELECT workspace_internal_id, network_internal_id
FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`
	lockKubernetesCompletionSQL = `SELECT request_internal_id, request_state, request_version,
    completion_deadline, reserved_ordinal, reserved_hostname, credential_internal_id, credential_state,
    cluster_internal_id, profile_internal_id, owner_principal_internal_id,
    device_public_id::TEXT, device_hostname, completed_network_revision,
    approver_public_id::TEXT, cluster_public_id::TEXT
FROM mesh_ops.lock_kubernetes_replica_completion_v1($1::UUID, $2::BYTEA, $3::BYTEA, $4::UUID)`
	insertKubernetesGatewayDeviceSQL = `SELECT device_internal_id, device_version
FROM mesh_ops.insert_kubernetes_gateway_device_v1($1::BIGINT, $2::UUID, $3::TEXT, $4::TIMESTAMPTZ)`
	completeKubernetesReplicaRequestSQL = `SELECT mesh_ops.complete_kubernetes_replica_request_v1(
    $1::BIGINT, $2::BIGINT, $3::UUID, $4::BIGINT, $5::TIMESTAMPTZ)`
	// The cluster's group the gateway joined when its Device was written
	// (schema 230); no row when the cluster has no group yet.
	kubernetesPolicyGroupEvidenceSQL = `SELECT group_public_id::TEXT, member_hash_before, member_hash_after,
    group_revision FROM mesh_ops.kubernetes_cluster_policy_group_evidence_v1($1::BIGINT)`
)

// KubernetesJoinCompletionStore completes a replica's approved request into
// its gateway Device (K1a1 plan §10.2) in one transaction that reuses
// registration's steps: name, addresses, key epochs, revision and evidence.
// The Device row itself is written by a migrator-owned function, the only
// writer of gateway Devices.
type KubernetesJoinCompletionStore struct {
	database registrationTransactionDatabase
	options  RegistrationTransactionOptions
}

var _ kubecluster.JoinCompletionStore = (*KubernetesJoinCompletionStore)(nil)

// NewKubernetesJoinCompletionStore uses the runtime pool's registration
// transactions.
func NewKubernetesJoinCompletionStore(pool *Pool,
	options RegistrationTransactionOptions) (*KubernetesJoinCompletionStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.registrationTransactionDatabase == nil ||
		!validRegistrationTransactionOptions(options) {
		return nil, kubecluster.ErrInvalid
	}
	return &KubernetesJoinCompletionStore{database: pool.registrationTransactionDatabase, options: options}, nil
}

// kubernetesCompletionLock is what the lock returned about one request.
type kubernetesCompletionLock struct {
	requestID, requestVersion, credentialID, clusterID int64
	profileID, ownerID                                 sql.NullInt64
	state                                              string
	deadline                                           sql.NullTime
	ordinal                                            sql.NullInt16
	reservedHostname, credentialState                  sql.NullString
	devicePublicID, deviceHostname                     sql.NullString
	completedRevision                                  sql.NullInt64
	approverPublicID                                   sql.NullString
	clusterPublicID                                    string
}

type kubernetesCompletionIDs struct {
	device, machineEpoch, nodeEpoch, v4Lease, v6Lease publicid.ID
	credentialUse, change, event, outbox              publicid.ID
}

func newKubernetesCompletionIDs() (kubernetesCompletionIDs, error) {
	var values [9]publicid.ID
	for index := range values {
		id, err := publicid.New()
		if err != nil {
			return kubernetesCompletionIDs{}, err
		}
		values[index] = id
	}
	return kubernetesCompletionIDs{device: values[0], machineEpoch: values[1], nodeEpoch: values[2],
		v4Lease: values[3], v6Lease: values[4], credentialUse: values[5], change: values[6], event: values[7],
		outbox: values[8]}, nil
}

// CompleteReplicaRequest completes the request, or reports where it stands.
func (store *KubernetesJoinCompletionStore) CompleteReplicaRequest(ctx context.Context, scope network.Scope,
	requestID kubecluster.RequestID, identity node.RegistrationIdentity) (_ kubecluster.Completion, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validRegistrationTransactionOptions(store.options) ||
		!scope.IsValid() || !requestID.IsValid() || !identity.IsValid() {
		return kubecluster.Completion{}, kubecluster.ErrInvalid
	}
	ids, err := newKubernetesCompletionIDs()
	if err != nil {
		return kubecluster.Completion{}, errors.Join(kubecluster.ErrUnavailable, err)
	}
	tx, err := store.database.Begin(ctx)
	if err != nil {
		return kubecluster.Completion{}, errors.Join(kubecluster.ErrUnavailable, err)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackRegistrationSetup(tx))
		}
	}()
	if _, err := tx.Exec(ctx, configureRegistrationTransactionSQL, postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.LockTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return kubecluster.Completion{}, errors.Join(kubecluster.ErrUnavailable, err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setKubernetesCompletionScopeSQL, scope.WorkspaceID().String(),
		scope.NetworkID().String()).Scan(&workspaceInternal, &networkInternal); err != nil ||
		workspaceInternal <= 0 || networkInternal <= 0 {
		return kubecluster.Completion{}, errors.Join(kubecluster.ErrUnavailable, err)
	}
	fingerprint := identity.MachineKey().Fingerprint()
	nodeKey := identity.NodeKey().Bytes()
	var lock kubernetesCompletionLock
	if err := tx.QueryRow(ctx, lockKubernetesCompletionSQL, requestID.String(), fingerprint[:], nodeKey[:],
		ids.change.String()).Scan(&lock.requestID, &lock.state, &lock.requestVersion, &lock.deadline,
		&lock.ordinal, &lock.reservedHostname, &lock.credentialID, &lock.credentialState, &lock.clusterID,
		&lock.profileID, &lock.ownerID, &lock.devicePublicID, &lock.deviceHostname, &lock.completedRevision,
		&lock.approverPublicID, &lock.clusterPublicID); err != nil {
		return kubecluster.Completion{}, kubernetesCompletionDatabaseError(err)
	}
	commit := func(completion kubecluster.Completion, outcome error) (kubecluster.Completion, error) {
		if err := tx.Commit(ctx); err != nil {
			return kubecluster.Completion{}, errors.Join(kubecluster.ErrUnavailable, err)
		}
		closed = true
		return completion, outcome
	}
	switch kubecluster.RequestState(lock.state) {
	case kubecluster.RequestPending:
		return commit(kubecluster.Completion{State: kubecluster.RequestPending}, nil)
	case kubecluster.RequestCompleted:
		result, err := completedKubernetesResult(scope, requestID, lock)
		if err != nil {
			return kubecluster.Completion{}, err
		}
		return commit(kubecluster.Completion{State: kubecluster.RequestCompleted, Result: result}, nil)
	case kubecluster.RequestExpired:
		// The lock reports a passed deadline without writing it.
		return kubecluster.Completion{}, kubecluster.ErrExpired
	case kubecluster.RequestApproved:
	default:
		return kubecluster.Completion{}, kubecluster.ErrNotWaiting
	}
	if lock.credentialState.String != "active" {
		return kubecluster.Completion{}, kubecluster.ErrKeyNotUsable
	}
	result, err := store.completeApproved(ctx, tx, scope, requestID, identity, lock, ids,
		workspaceInternal, networkInternal)
	if err != nil {
		return kubecluster.Completion{}, err
	}
	return commit(kubecluster.Completion{State: kubecluster.RequestCompleted, Result: result}, nil)
}

func completedKubernetesResult(scope network.Scope, requestID kubecluster.RequestID,
	lock kubernetesCompletionLock) (registration.Result, error) {
	deviceID, err := node.ParseID(lock.devicePublicID.String)
	hostname, hostnameErr := node.ParseHostname(lock.deviceHostname.String)
	if err != nil || hostnameErr != nil || !lock.completedRevision.Valid || lock.completedRevision.Int64 <= 0 {
		return registration.Result{}, kubecluster.ErrInvalid
	}
	result, err := registration.NewResult(enrollment.RegistrationID(publicid.ID(requestID)), scope, deviceID,
		hostname, registration.DispositionCreated, lock.completedRevision.Int64)
	if err != nil {
		return registration.Result{}, kubecluster.ErrInvalid
	}
	return result, nil
}

// completeApproved writes the gateway Device: name, addresses, Device, key
// epochs, leases, revision, request, evidence.
func (store *KubernetesJoinCompletionStore) completeApproved(ctx context.Context, tx registrationDatabaseTransaction,
	scope network.Scope, requestID kubecluster.RequestID, identity node.RegistrationIdentity,
	lock kubernetesCompletionLock, ids kubernetesCompletionIDs, workspaceInternal, networkInternal int64,
) (registration.Result, error) {
	reserved, err := node.ParseHostname(lock.reservedHostname.String)
	if err != nil || !lock.ownerID.Valid || lock.ownerID.Int64 <= 0 || !lock.ordinal.Valid {
		return registration.Result{}, kubecluster.ErrInvalid
	}
	var networkRevision, inventoryRevision, group, policy, dns, route, sharing, isolation int64
	if err := tx.QueryRow(ctx, lockRegistrationNetworkRevisionSQL).Scan(&networkRevision, &inventoryRevision,
		&group, &policy, &dns, &route, &sharing, &isolation); err != nil || networkRevision <= 0 ||
		inventoryRevision <= 0 {
		return registration.Result{}, errors.Join(ErrRegistrationEvidence, err)
	}
	helper := &registrationTransaction{database: tx, scope: scope, workspaceInternalID: workspaceInternal,
		networkInternalID: networkInternal, candidateLimit: store.options.AddressCandidateLimit}
	// The reserved name, or its next free variant if a Device took it since.
	helper.locked.hostnameOwner = lock.ownerID.Int64
	if err := helper.selectHostname(ctx, &helper.locked, reserved); err != nil {
		return registration.Result{}, err
	}
	if err := helper.lockAddressState(ctx, &helper.locked); err != nil {
		return registration.Result{}, err
	}
	hostname := helper.locked.hostname
	leasing, err := helper.allocateRegistrationLeases()
	if err != nil {
		return registration.Result{}, err
	}
	if err := helper.lockAuditHead(ctx, &helper.locked); err != nil {
		return registration.Result{}, err
	}
	var occurredAt time.Time
	if err := tx.QueryRow(ctx, browserCompletionTimeSQL).Scan(&occurredAt); err != nil || occurredAt.IsZero() {
		return registration.Result{}, errors.Join(ErrRegistrationEvidence, err)
	}
	if _, err := tx.Exec(ctx, setRegistrationChangeSQL, ids.change.String()); err != nil {
		return registration.Result{}, err
	}
	if err := helper.releaseHostname(ctx, hostname); err != nil {
		return registration.Result{}, err
	}
	var deviceInternal, deviceVersion int64
	if err := tx.QueryRow(ctx, insertKubernetesGatewayDeviceSQL, lock.requestID, ids.device.String(),
		hostname.String(), occurredAt).Scan(&deviceInternal, &deviceVersion); err != nil ||
		deviceInternal <= 0 || deviceVersion != 1 {
		if err != nil {
			return registration.Result{}, kubernetesCompletionDatabaseError(err)
		}
		return registration.Result{}, ErrRegistrationEvidence
	}
	machineKey, nodeKey := identity.MachineKey().Bytes(), identity.NodeKey().Bytes()
	machineFingerprint, nodeFingerprint := identity.MachineKey().Fingerprint(), identity.NodeKey().Fingerprint()
	for _, key := range []struct {
		query                 string
		id                    publicid.ID
		material, fingerprint [32]byte
	}{
		{insertRegistrationMachineKeySQL, ids.machineEpoch, machineKey, machineFingerprint},
		{insertRegistrationNodeKeySQL, ids.nodeEpoch, nodeKey, nodeFingerprint},
	} {
		if _, err := tx.Exec(ctx, key.query, key.id.String(), workspaceInternal, networkInternal, deviceInternal,
			key.material[:], key.fingerprint[:], occurredAt); err != nil {
			return registration.Result{}, err
		}
	}
	for _, lease := range leasing {
		leaseID := ids.v4Lease
		if lease.family == 6 {
			leaseID = ids.v6Lease
		}
		if err := releaseReclaimedRegistrationLease(ctx, tx, lease, occurredAt); err != nil {
			return registration.Result{}, err
		}
		if _, err := tx.Exec(ctx, insertRegistrationLeaseSQL, leaseID.String(), workspaceInternal, networkInternal,
			lease.prefix.realmInternalID, lease.prefix.poolInternalID, lease.prefix.internalID, deviceInternal,
			lease.address.String(), lease.family, occurredAt); err != nil {
			return registration.Result{}, err
		}
	}
	if err := helper.storeAddressFloors(ctx); err != nil {
		return registration.Result{}, err
	}
	var newNetworkRevision, newInventoryRevision int64
	if err := tx.QueryRow(ctx, advanceRegistrationRevisionSQL).Scan(&newNetworkRevision,
		&newInventoryRevision); err != nil || newNetworkRevision != networkRevision+1 ||
		newInventoryRevision != inventoryRevision+1 {
		return registration.Result{}, errors.Join(ErrRegistrationEvidence, err)
	}
	var completed bool
	if err := tx.QueryRow(ctx, completeKubernetesReplicaRequestSQL, lock.requestID, deviceInternal,
		ids.credentialUse.String(), newNetworkRevision, occurredAt).Scan(&completed); err != nil || !completed {
		if err != nil {
			return registration.Result{}, kubernetesCompletionDatabaseError(err)
		}
		return registration.Result{}, ErrRegistrationEvidence
	}
	joined, err := readKubernetesPolicyGroupEvidence(ctx, tx, deviceInternal)
	if err != nil {
		return registration.Result{}, err
	}
	if err := appendKubernetesEnrolledEvidence(ctx, tx, helper.locked.audit, lock, requestID, ids, hostname,
		deviceVersion, newNetworkRevision, newInventoryRevision, joined); err != nil {
		return registration.Result{}, err
	}
	deviceID, err := node.ParseID(ids.device.String())
	if err != nil {
		return registration.Result{}, ErrRegistrationEvidence
	}
	return registration.NewResult(enrollment.RegistrationID(publicid.ID(requestID)), scope, deviceID, hostname,
		registration.DispositionCreated, newNetworkRevision)
}

// appendKubernetesEnrolledEvidence records kubernetes_replica.enrolled on
// the Network's stream with the approver as actor, as registration records
// device.registered.
func appendKubernetesEnrolledEvidence(ctx context.Context, tx registrationDatabaseTransaction,
	head registrationAuditHead, lock kubernetesCompletionLock, requestID kubecluster.RequestID,
	ids kubernetesCompletionIDs, hostname node.Hostname, deviceVersion, networkRevision, inventoryRevision int64,
	group *kubernetesPolicyGroupEvidence,
) error {
	approver, err := publicid.Parse(lock.approverPublicID.String)
	if err != nil {
		return ErrRegistrationEvidence
	}
	auditPayload, err := json.Marshal(struct {
		Hostname  string                         `json:"hostname"`
		RequestID string                         `json:"request_id"`
		ClusterID string                         `json:"cluster_id"`
		Ordinal   int16                          `json:"ordinal"`
		Group     *kubernetesPolicyGroupEvidence `json:"policy_group,omitempty"`
	}{hostname.String(), requestID.String(), lock.clusterPublicID, lock.ordinal.Int16, group})
	if err != nil {
		return err
	}
	outboxPayload, err := json.Marshal(registrationOutboxPayload{
		InventoryRevision: inventoryRevision, NetworkRevision: networkRevision,
	})
	if err != nil {
		return err
	}
	semanticHash := sha256.Sum256([]byte(requestID.String() + "\x00" + ids.device.String() + "\x00" +
		hostname.String()))
	const action = "kubernetes_replica.enrolled"
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: head.previousHash, EventID: ids.event, ChangeID: ids.change,
		AggregateKind: "device", AggregateID: ids.device, AggregateVersion: deviceVersion,
		NetworkRevision: networkRevision, ActorPrincipalID: approver, Action: action,
		Permission: "kubernetes_cluster.approve", CorrelationID: publicid.ID(requestID),
		AfterSemanticHash: semanticHash, AuditPayloadHash: sha256.Sum256(auditPayload),
		OutboxEventClass: registrationOutboxEventClass, OutboxPayloadHash: sha256.Sum256(outboxPayload),
	})
	if err != nil {
		return err
	}
	var sequence int64
	if err := tx.QueryRow(ctx, appendRegistrationEvidenceSQL, head.streamInternalID, ids.event.String(),
		ids.outbox.String(), head.nextSequence, head.previousHash[:], eventHash[:], ids.device.String(),
		deviceVersion, networkRevision, approver.String(), action, requestID.String(), semanticHash[:],
		auditPayload, outboxPayload).Scan(&sequence); err != nil || sequence != head.nextSequence {
		return errors.Join(ErrRegistrationEvidence, err)
	}
	return nil
}

func kubernetesCompletionDatabaseError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "P0002":
			return kubecluster.ErrNotFound
		case "MTK10":
			return kubecluster.ErrNotWaiting
		// MTK11: a rule to the cluster would give a Device too many edges
		// with this replica; the replica asks again.
		case "MTK11":
			return errors.Join(kubecluster.ErrEdgeBudget, err)
		case "40001", "40P01":
			return kubecluster.ErrConflict
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return kubecluster.ErrNotFound
	}
	return errors.Join(kubecluster.ErrUnavailable, err)
}

// kubernetesPolicyGroupEvidence is the cluster's group a new gateway joined:
// its members without and with the gateway, and the group revision.
type kubernetesPolicyGroupEvidence struct {
	GroupID          string `json:"group_id"`
	MemberHashBefore string `json:"member_set_sha256_before"`
	MemberHashAfter  string `json:"member_set_sha256"`
	GroupRevision    int64  `json:"group_revision"`
}

func readKubernetesPolicyGroupEvidence(ctx context.Context, tx registrationDatabaseTransaction,
	deviceInternal int64) (*kubernetesPolicyGroupEvidence, error) {
	var groupID string
	var before, after []byte
	var revision int64
	err := tx.QueryRow(ctx, kubernetesPolicyGroupEvidenceSQL, deviceInternal).Scan(&groupID, &before, &after, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, kubernetesCompletionDatabaseError(err)
	}
	if _, parseErr := publicid.Parse(groupID); parseErr != nil || len(before) != sha256.Size ||
		len(after) != sha256.Size || revision <= 0 {
		return nil, ErrRegistrationEvidence
	}
	return &kubernetesPolicyGroupEvidence{GroupID: groupID, MemberHashBefore: hex.EncodeToString(before),
		MemberHashAfter: hex.EncodeToString(after), GroupRevision: revision}, nil
}

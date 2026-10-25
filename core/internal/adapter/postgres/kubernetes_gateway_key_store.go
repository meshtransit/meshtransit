package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	resolveGatewaySessionScopeSQL = `SELECT workspace_public_id::TEXT, network_public_id::TEXT
FROM mesh_ops.resolve_map_session_scope($1::BYTEA, $2::BYTEA)`
	rotateGatewayMachineKeySQL = `SELECT device_public_id::TEXT, previous_device_version, device_version,
    machine_key_epoch, session_generation, limited_until
FROM mesh_ops.rotate_kubernetes_gateway_machine_key_v1(
    $1::BYTEA, $2::BYTEA, $3::BYTEA, $4::BYTEA, $5::UUID, $6::UUID)`
	appendGatewayKeyRotationEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'device', $7::UUID, $8::BIGINT, $9::BIGINT, NULL::UUID,
    'device.machine_key_rotated', 'device.machine_key.rotate', $10::UUID,
    $11::BYTEA, $12::BYTEA, $13::JSONB,
    'network.revision.advanced', $14::JSONB
)`
)

// KubernetesGatewayKeyStore rotates Kubernetes gateways' machine keys
// (mtcp-v1 §6.8): in one transaction under the Network revision lock, with
// device.machine_key_rotated as evidence. The key epochs, the history and
// the former key's timestamp are written by a migrator-owned function.
type KubernetesGatewayKeyStore struct {
	database registrationTransactionDatabase
	options  RegistrationTransactionOptions
}

var _ kubecluster.MachineKeyRotations = (*KubernetesGatewayKeyStore)(nil)

// NewKubernetesGatewayKeyStore uses the runtime pool's registration
// transactions.
func NewKubernetesGatewayKeyStore(pool *Pool,
	options RegistrationTransactionOptions) (*KubernetesGatewayKeyStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.registrationTransactionDatabase == nil ||
		!validRegistrationTransactionOptions(options) {
		return nil, kubecluster.ErrInvalid
	}
	return &KubernetesGatewayKeyStore{database: pool.registrationTransactionDatabase, options: options}, nil
}

// gatewayKeyRotationRow is what the rotation function returned.
type gatewayKeyRotationRow struct {
	devicePublicID        string
	previousDeviceVersion int64
	deviceVersion         int64
	machineKeyEpoch       int64
	sessionGeneration     int64
	limitedUntil          sql.NullTime
}

// RotateGatewayMachineKey implements kubecluster.MachineKeyRotations.
func (store *KubernetesGatewayKeyStore) RotateGatewayMachineKey(ctx context.Context,
	rotation kubecluster.MachineKeyRotation) (resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validRegistrationTransactionOptions(store.options) ||
		!rotation.IsValid() {
		return kubecluster.ErrInvalid
	}
	var ids [4]publicid.ID // epoch, change, event, outbox
	for index := range ids {
		id, err := publicid.New()
		if err != nil {
			return errors.Join(kubecluster.ErrUnavailable, err)
		}
		ids[index] = id
	}
	tx, err := store.database.Begin(ctx)
	if err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackRegistrationSetup(tx))
		}
	}()
	if _, err := tx.Exec(ctx, configureRegistrationTransactionSQL, postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.LockTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	fingerprint := rotation.MachineKey.Fingerprint()
	nodeKey := rotation.NodeKey.Bytes()
	// The session proved these keys (mtcp-v1 §6.7): only such a session
	// rotates a gateway.
	if _, err := tx.Exec(ctx, markSessionProvenSQL, fingerprint[:], nodeKey[:]); err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	var workspaceID, networkID string
	if err := tx.QueryRow(ctx, resolveGatewaySessionScopeSQL, fingerprint[:], nodeKey[:]).Scan(&workspaceID,
		&networkID); err != nil {
		return gatewayKeyDatabaseError(err)
	}
	var workspaceInternal, networkInternal int64
	if err := tx.QueryRow(ctx, setKubernetesCompletionScopeSQL, workspaceID, networkID).Scan(&workspaceInternal,
		&networkInternal); err != nil || workspaceInternal <= 0 || networkInternal <= 0 {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	var networkRevision, inventoryRevision, group, policy, dns, route, sharing, isolation int64
	if err := tx.QueryRow(ctx, lockRegistrationNetworkRevisionSQL).Scan(&networkRevision, &inventoryRevision,
		&group, &policy, &dns, &route, &sharing, &isolation); err != nil {
		return gatewayKeyDatabaseError(err)
	}
	newKey := rotation.NewMachineKey.Bytes()
	newFingerprint := rotation.NewMachineKey.Fingerprint()
	var row gatewayKeyRotationRow
	if err := tx.QueryRow(ctx, rotateGatewayMachineKeySQL, fingerprint[:], nodeKey[:], newKey[:],
		newFingerprint[:], ids[0].String(), ids[1].String()).Scan(&row.devicePublicID, &row.previousDeviceVersion,
		&row.deviceVersion, &row.machineKeyEpoch, &row.sessionGeneration, &row.limitedUntil); err != nil {
		return gatewayKeyDatabaseError(err)
	}
	if row.limitedUntil.Valid {
		var now time.Time
		if err := tx.QueryRow(ctx, browserCompletionTimeSQL).Scan(&now); err != nil {
			return errors.Join(kubecluster.ErrUnavailable, err)
		}
		return &kubecluster.RotationLimitedError{RetryAfter: max(time.Second, row.limitedUntil.Time.Sub(now))}
	}
	deviceID, err := publicid.Parse(row.devicePublicID)
	if err != nil || row.deviceVersion != row.previousDeviceVersion+1 || row.machineKeyEpoch < 2 {
		return errors.Join(kubecluster.ErrUnavailable, ErrRegistrationEvidence, err)
	}
	var head registrationAuditHead
	var previousHash []byte
	if err := tx.QueryRow(ctx, lockRegistrationAuditStreamSQL).Scan(&head.streamInternalID, &head.nextSequence,
		&previousHash); err != nil || head.streamInternalID <= 0 || head.nextSequence <= 0 || len(previousHash) != 32 {
		return errors.Join(kubecluster.ErrUnavailable, ErrRegistrationEvidence, err)
	}
	copy(head.previousHash[:], previousHash)
	if err := tx.QueryRow(ctx, advanceRegistrationRevisionSQL).Scan(&networkRevision,
		&inventoryRevision); err != nil || networkRevision <= 0 || inventoryRevision <= 0 {
		return errors.Join(kubecluster.ErrUnavailable, ErrRegistrationEvidence, err)
	}
	if err := appendGatewayKeyRotationEvidence(ctx, tx, head, rotation, deviceID, row, ids,
		networkRevision, inventoryRevision); err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(kubecluster.ErrUnavailable, err)
	}
	closed = true
	return nil
}

func appendGatewayKeyRotationEvidence(ctx context.Context, tx registrationDatabaseTransaction,
	head registrationAuditHead, rotation kubecluster.MachineKeyRotation, deviceID publicid.ID,
	row gatewayKeyRotationRow, ids [4]publicid.ID, networkRevision, inventoryRevision int64) error {
	auditPayload, err := json.Marshal(struct {
		AuthenticationKind        string `json:"authentication_kind"`
		PreviousDeviceVersion     int64  `json:"previous_device_version"`
		DeviceVersion             int64  `json:"device_version"`
		PreviousMachineKeyEpoch   int64  `json:"previous_machine_key_epoch"`
		MachineKeyEpoch           int64  `json:"machine_key_epoch"`
		PreviousSessionGeneration int64  `json:"previous_session_generation"`
		SessionGeneration         int64  `json:"session_generation"`
	}{"noise_machine_key_and_node_key_proof", row.previousDeviceVersion, row.deviceVersion,
		row.machineKeyEpoch - 1, row.machineKeyEpoch, row.sessionGeneration - 1, row.sessionGeneration})
	if err != nil {
		return err
	}
	outboxPayload, err := json.Marshal(registrationOutboxPayload{
		InventoryRevision: inventoryRevision, NetworkRevision: networkRevision,
	})
	if err != nil {
		return err
	}
	previous := rotation.MachineKey.Fingerprint()
	next := rotation.NewMachineKey.Fingerprint()
	before := sha256.Sum256(append([]byte("meshtransit/machine-key-state/v1\x00"), previous[:]...))
	after := sha256.Sum256(append([]byte("meshtransit/machine-key-state/v1\x00"), next[:]...))
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: head.previousHash, EventID: ids[2], ChangeID: ids[1],
		AggregateKind: "device", AggregateID: deviceID, AggregateVersion: row.deviceVersion,
		NetworkRevision: networkRevision, Action: "device.machine_key_rotated",
		Permission: "device.machine_key.rotate", CorrelationID: rotation.OperationID,
		BeforeSemanticHash: before, AfterSemanticHash: after, AuditPayloadHash: sha256.Sum256(auditPayload),
		OutboxEventClass: registrationOutboxEventClass, OutboxPayloadHash: sha256.Sum256(outboxPayload),
	})
	if err != nil {
		return err
	}
	var sequence int64
	if err := tx.QueryRow(ctx, appendGatewayKeyRotationEvidenceSQL, head.streamInternalID, ids[2].String(),
		ids[3].String(), head.nextSequence, head.previousHash[:], eventHash[:], deviceID.String(),
		row.deviceVersion, networkRevision, rotation.OperationID.String(), before[:], after[:], auditPayload,
		outboxPayload).Scan(&sequence); err != nil || sequence != head.nextSequence {
		return errors.Join(ErrRegistrationEvidence, err)
	}
	return nil
}

func gatewayKeyDatabaseError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return kubecluster.ErrNotFound
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "P0002":
			return kubecluster.ErrNotFound
		case "MTK13":
			return kubecluster.ErrMachineKeyUsed
		case "23505":
			// Another rotation took the same new key meanwhile; any other
			// duplicate is not about the key.
			switch pgError.ConstraintName {
			case "kubernetes_gateway_machine_key_history_pkey", "device_machine_key_epoch_key_active_uidx":
				return kubecluster.ErrMachineKeyUsed
			}
		case "40001", "40P01", "55P03":
			return kubecluster.ErrConflict
		}
	}
	return errors.Join(kubecluster.ErrUnavailable, err)
}

package postgres

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/node"
)

// Exact RLS scope is installed by the approved completion authority. Historical
// keys remain visible here so a revoked machine cannot become a fresh Device,
// except one its owner moved to another Network (sign-in-moves-machine §5.2).
// An active key comes first: a machine that came back holds an active Device
// beside the one it left.
const lockBrowserResumeDeviceSQL = `SELECT
    device.id, device.public_id::TEXT, device.enrollment_profile_id,
    device.hostname, device.version, machine.public_key,
    device.owner_principal_id, device.state, machine.state,
    device.deleted_at IS NULL AND machine.valid_from <= pg_catalog.clock_timestamp()
      AND device.is_ephemeral=$2::BOOLEAN,
    COALESCE(device.suspended_reason, ''), COALESCE(device.handover_principal_id, 0),
    device.signed_out_at IS NOT NULL, COALESCE(machine.revocation_reason, ''),
    device.state='revoked' AND mesh_ops.browser_device_moved_v1(device.id)
FROM mesh.device_machine_key_epoch machine
JOIN mesh.device device ON device.workspace_id=machine.workspace_id
 AND device.network_id=machine.network_id AND device.id=machine.device_id
WHERE machine.fingerprint=$1::BYTEA
ORDER BY machine.state='active' DESC, machine.epoch DESC, machine.id DESC
LIMIT 1
FOR UPDATE OF device, machine`

// movedRevocation is the revocation reason of a Device its owner moved to
// another Network by signing in there (schema 290).
const movedRevocation = "moved"

const lockBrowserResumeNodeSQL = `SELECT node_key.public_key, node_key.id, node_key.epoch, node_key.version,
    device.session_generation
FROM mesh.device_node_key_epoch node_key
JOIN mesh.device device ON device.workspace_id=node_key.workspace_id
 AND device.network_id=node_key.network_id AND device.id=node_key.device_id
WHERE node_key.device_id=$1::BIGINT AND node_key.state='active'
  AND node_key.valid_from <= pg_catalog.clock_timestamp()
  AND device.current_node_key_epoch=node_key.epoch
FOR UPDATE OF node_key`

// A sign-in with a new Node key ends the Device's key the way a rotation
// does (node_key_rotation_sql.go), without a rotation proof: the person's
// approval and the Noise-proven machine key stand in for it.
const expireBrowserResumeNodeKeySQL = `UPDATE mesh.device_node_key_epoch
SET state='expired', valid_until=GREATEST($3::TIMESTAMPTZ, valid_from),
    version=version+1, updated_at=GREATEST($3::TIMESTAMPTZ, updated_at)
WHERE id=$1::BIGINT AND version=$2::BIGINT AND state='active' AND valid_until IS NULL
RETURNING version`

const insertBrowserResumeNodeKeySQL = `INSERT INTO mesh.device_node_key_epoch (
    public_id, workspace_id, network_id, device_id, epoch,
    public_key, fingerprint, valid_from, state, created_at, updated_at
) VALUES (
    $1::UUID, $2::BIGINT, $3::BIGINT, $4::BIGINT, $5::BIGINT,
    $6::BYTEA, $7::BYTEA, $8::TIMESTAMPTZ, 'active', $8::TIMESTAMPTZ, $8::TIMESTAMPTZ
)`

const rotateBrowserResumeDeviceSQL = `UPDATE mesh.device
SET current_node_key_epoch=$3::BIGINT, session_generation=session_generation+1,
    version=version+1, updated_at=GREATEST($4::TIMESTAMPTZ, updated_at)
WHERE id=$1::BIGINT AND version=$2::BIGINT AND current_node_key_epoch=$3::BIGINT-1
  AND state='active' AND deleted_at IS NULL
RETURNING version`

// Signing in again ends a sign-out (schema 283).
const resumeBrowserDeviceSQL = `UPDATE mesh.device
SET expires_at=$2::TIMESTAMPTZ, signed_out_at=NULL, updated_at=$3::TIMESTAMPTZ, version=version+1
WHERE id=$1::BIGINT AND version=$4::BIGINT
  AND owner_principal_id=$5::BIGINT AND enrollment_profile_id=$6::BIGINT
  AND state='active' AND deleted_at IS NULL
RETURNING version`

// Completes a handover: the member the Device waited for becomes its owner,
// and its old sessions end (schema 125).
const handoverBrowserDeviceSQL = `UPDATE mesh.device
SET owner_principal_id=$5::BIGINT, custodian_principal_id=$5::BIGINT, ownership='member',
    state='active', suspended_reason=NULL, handover_principal_id=NULL,
    expires_at=$2::TIMESTAMPTZ, signed_out_at=NULL, session_generation=session_generation+1,
    updated_at=$3::TIMESTAMPTZ, version=version+1
WHERE id=$1::BIGINT AND version=$4::BIGINT
  AND state='suspended' AND suspended_reason='handover' AND handover_principal_id=$5::BIGINT
  AND enrollment_profile_id=$6::BIGINT AND deleted_at IS NULL
RETURNING version`

const browserCompletionTimeSQL = `SELECT pg_catalog.clock_timestamp()`

func lockBrowserResumeDevice(ctx context.Context, tx registrationDatabaseTransaction,
	identity node.RegistrationIdentity, authority browserCompletionAuthority,
) (bool, registrationDeviceRecord, error) {
	var record registrationDeviceRecord
	var owner, handoverTo int64
	var deviceState, machineState, suspendedReason, revocationReason string
	var current, movedByOwner bool
	fingerprint := identity.MachineKey().Fingerprint()
	err := tx.QueryRow(ctx, lockBrowserResumeDeviceSQL, fingerprint[:], authority.ephemeralMode == "ephemeral").Scan(
		&record.internalID, &record.publicID, &record.profileInternalID,
		&record.hostname, &record.version, &record.machineKey, &owner,
		&deviceState, &machineState, &current, &suspendedReason, &handoverTo, &record.signedOut,
		&revocationReason, &movedByOwner,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, registrationDeviceRecord{}, nil
	}
	if err != nil {
		return false, registrationDeviceRecord{}, err
	}
	// The owner moved this machine away and now brings it back: a new Device.
	// Only a move marks a Device moved (schema 290); an administrator's
	// revocation reason, whatever its text, never does.
	if movedByOwner && deviceState == "revoked" && machineState == "revoked" &&
		revocationReason == movedRevocation && owner == authority.principalInternalID {
		return false, registrationDeviceRecord{}, nil
	}
	machine := identity.MachineKey().Bytes()
	// The owner resumes an active Device; the member a handover waits for
	// resumes the suspended Device and becomes its owner.
	ownerResume := owner == authority.principalInternalID && deviceState == "active"
	record.handover = deviceState == "suspended" && suspendedReason == "handover" &&
		handoverTo == authority.principalInternalID
	if record.internalID <= 0 || record.version <= 0 || !current || (!ownerResume && !record.handover) ||
		record.profileInternalID != authority.profileInternalID ||
		machineState != "active" || !bytes.Equal(record.machineKey, machine[:]) {
		return false, registrationDeviceRecord{}, ErrBrowserCompletionConflict
	}
	if err := tx.QueryRow(ctx, lockBrowserResumeNodeSQL, record.internalID).Scan(&record.nodeKey,
		&record.nodeEpochInternalID, &record.nodeEpoch, &record.nodeEpochVersion, &record.sessionGeneration); err != nil {
		// No active node key: a Device this approval cannot resume. Any other
		// error (a lock or statement timeout) is retried, never refused.
		if errors.Is(err, pgx.ErrNoRows) {
			return false, registrationDeviceRecord{}, ErrBrowserCompletionConflict
		}
		return false, registrationDeviceRecord{}, err
	}
	key := identity.NodeKey().Bytes()
	if !bytes.Equal(record.nodeKey, key[:]) {
		// A new key for this sign-in (sign-in-moves-machine §5.1). A key the
		// Device or any other ever held fails the history index instead.
		if record.nodeEpochInternalID <= 0 || record.nodeEpoch <= 0 || record.nodeEpochVersion <= 0 ||
			record.sessionGeneration <= 0 {
			return false, registrationDeviceRecord{}, ErrRegistrationEvidence
		}
		record.rotateNodeKey = true
		record.nodeKey = append([]byte(nil), key[:]...)
	}
	return true, record, nil
}

// rotateBrowserResumeNodeKey replaces the resumed Device's Node key with the
// sign-in's, and returns the Device's version after it.
func rotateBrowserResumeNodeKey(ctx context.Context, tx registrationDatabaseTransaction,
	record registrationDeviceRecord, identity node.RegistrationIdentity, workspaceInternalID,
	networkInternalID, deviceVersion int64, epochID string, occurredAt time.Time,
) (int64, error) {
	var expiredVersion int64
	if err := tx.QueryRow(ctx, expireBrowserResumeNodeKeySQL, record.nodeEpochInternalID,
		record.nodeEpochVersion, occurredAt).Scan(&expiredVersion); err != nil ||
		expiredVersion != record.nodeEpochVersion+1 {
		return 0, errors.Join(ErrRegistrationEvidence, err)
	}
	key := identity.NodeKey().Bytes()
	fingerprint := identity.NodeKey().Fingerprint()
	if _, err := tx.Exec(ctx, insertBrowserResumeNodeKeySQL, epochID, workspaceInternalID,
		networkInternalID, record.internalID, record.nodeEpoch+1, key[:], fingerprint[:], occurredAt,
	); err != nil {
		return 0, keysHeldElsewhere(err)
	}
	var version int64
	// The version guard orders this after the resume; a handover's resume
	// already advanced the session generation (review H2).
	if err := tx.QueryRow(ctx, rotateBrowserResumeDeviceSQL, record.internalID, deviceVersion,
		record.nodeEpoch+1, occurredAt).Scan(&version); err != nil ||
		version != deviceVersion+1 {
		return 0, errors.Join(ErrRegistrationEvidence, err)
	}
	return version, nil
}

// Authority rows remain locked; this second read also guards against time
// expiring while Device, address or audit locks were being acquired.
func recheckBrowserCompletion(ctx context.Context, tx registrationDatabaseTransaction,
	deploymentID deployment.ID, epoch int64, identity node.RegistrationIdentity,
	hostname node.Hostname, digest enrollment.BrowserIntentDigest,
	expected browserCompletionAuthority,
) error {
	machine := identity.MachineKey().Bytes()
	fingerprint := identity.MachineKey().Fingerprint()
	key := identity.NodeKey().Bytes()
	proof := digest.Bytes()
	var actual browserCompletionAuthority
	err := tx.QueryRow(ctx, lockBrowserCompletionSQL, deploymentID.String(), epoch,
		proof[:], machine[:], fingerprint[:], key[:], hostname.String(),
	).Scan(
		&actual.intentInternalID, &actual.intentPublicID,
		&actual.registrationInternalID, &actual.registrationPublicID,
		&actual.registrationVersion, &actual.workspaceInternalID, &actual.workspacePublicID,
		&actual.networkInternalID, &actual.networkPublicID, &actual.profileInternalID,
		&actual.profilePublicID, &actual.principalInternalID, &actual.principalPublicID,
		&actual.sessionPublicID, &actual.currentNetworkRevision, &actual.lifetimeSeconds,
		&actual.ephemeralMode, &actual.requestHash,
	)
	if err != nil {
		return errors.Join(ErrRegistrationEvidence, err)
	}
	if !bytes.Equal(actual.requestHash, expected.requestHash) {
		return ErrRegistrationEvidence
	}
	// These structs contain a slice; compare every scalar after the digest check.
	if actual.intentInternalID != expected.intentInternalID || actual.intentPublicID != expected.intentPublicID ||
		actual.registrationInternalID != expected.registrationInternalID || actual.registrationPublicID != expected.registrationPublicID ||
		actual.registrationVersion != expected.registrationVersion || actual.workspaceInternalID != expected.workspaceInternalID ||
		actual.workspacePublicID != expected.workspacePublicID || actual.networkInternalID != expected.networkInternalID ||
		actual.networkPublicID != expected.networkPublicID || actual.profileInternalID != expected.profileInternalID ||
		actual.profilePublicID != expected.profilePublicID || actual.principalInternalID != expected.principalInternalID ||
		actual.principalPublicID != expected.principalPublicID || actual.sessionPublicID != expected.sessionPublicID ||
		actual.currentNetworkRevision != expected.currentNetworkRevision || actual.lifetimeSeconds != expected.lifetimeSeconds ||
		actual.ephemeralMode != expected.ephemeralMode {
		return ErrRegistrationEvidence
	}
	return nil
}

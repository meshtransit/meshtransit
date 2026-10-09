package postgres

import (
	"bytes"
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/node"
)

// Exact RLS scope is installed by the approved completion authority. Historical
// keys remain visible here so a revoked machine cannot become a fresh Device.
const lockBrowserResumeDeviceSQL = `SELECT
    device.id, device.public_id::TEXT, device.enrollment_profile_id,
    device.hostname, device.version, machine.public_key,
    device.owner_principal_id, device.state, machine.state,
    device.deleted_at IS NULL AND machine.valid_from <= pg_catalog.clock_timestamp()
      AND device.is_ephemeral=$2::BOOLEAN,
    COALESCE(device.suspended_reason, ''), COALESCE(device.handover_principal_id, 0)
FROM mesh.device_machine_key_epoch machine
JOIN mesh.device device ON device.workspace_id=machine.workspace_id
 AND device.network_id=machine.network_id AND device.id=machine.device_id
WHERE machine.fingerprint=$1::BYTEA
ORDER BY machine.epoch DESC, machine.id DESC
LIMIT 1
FOR UPDATE OF device, machine`

const lockBrowserResumeNodeSQL = `SELECT public_key
FROM mesh.device_node_key_epoch
WHERE device_id=$1::BIGINT AND state='active'
  AND valid_from <= pg_catalog.clock_timestamp()
FOR UPDATE`

const resumeBrowserDeviceSQL = `UPDATE mesh.device
SET expires_at=$2::TIMESTAMPTZ, updated_at=$3::TIMESTAMPTZ, version=version+1
WHERE id=$1::BIGINT AND version=$4::BIGINT
  AND owner_principal_id=$5::BIGINT AND enrollment_profile_id=$6::BIGINT
  AND state='active' AND deleted_at IS NULL
RETURNING version`

// Completes a handover: the member the Device waited for becomes its owner,
// and its old sessions end (schema 125).
const handoverBrowserDeviceSQL = `UPDATE mesh.device
SET owner_principal_id=$5::BIGINT, custodian_principal_id=$5::BIGINT, ownership='member',
    state='active', suspended_reason=NULL, handover_principal_id=NULL,
    expires_at=$2::TIMESTAMPTZ, session_generation=session_generation+1,
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
	var deviceState, machineState, suspendedReason string
	var current bool
	fingerprint := identity.MachineKey().Fingerprint()
	err := tx.QueryRow(ctx, lockBrowserResumeDeviceSQL, fingerprint[:], authority.ephemeralMode == "ephemeral").Scan(
		&record.internalID, &record.publicID, &record.profileInternalID,
		&record.hostname, &record.version, &record.machineKey, &owner,
		&deviceState, &machineState, &current, &suspendedReason, &handoverTo,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, registrationDeviceRecord{}, nil
	}
	if err != nil {
		return false, registrationDeviceRecord{}, err
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
	if err := tx.QueryRow(ctx, lockBrowserResumeNodeSQL, record.internalID).Scan(&record.nodeKey); err != nil {
		return false, registrationDeviceRecord{}, errors.Join(ErrBrowserCompletionConflict, err)
	}
	key := identity.NodeKey().Bytes()
	if !bytes.Equal(record.nodeKey, key[:]) {
		return false, registrationDeviceRecord{}, ErrBrowserCompletionConflict
	}
	return true, record, nil
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

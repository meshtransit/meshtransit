package postgres

import (
	"context"
	"fmt"
	"time"

	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
)

func (transaction *registrationTransaction) persistRegistrationDevice(
	ctx context.Context,
	change registration.Change,
	hostname node.Hostname,
	expiresAt time.Time,
) (internalID int64, version int64, resultErr error) {
	if err := transaction.releaseHostname(ctx, hostname); err != nil {
		return 0, 0, err
	}
	if change.Disposition() == registration.DispositionResumed {
		internalID = transaction.locked.device.internalID
		if err := transaction.database.QueryRow(
			ctx,
			resumeRegistrationDeviceSQL,
			internalID,
			hostname.String(),
			expiresAt,
			change.OccurredAt(),
			transaction.locked.device.version,
		).Scan(&version); err != nil {
			return 0, 0, fmt.Errorf("resume Device: %w", err)
		}
		if version != transaction.locked.device.version+1 {
			return 0, 0, ErrRegistrationEvidence
		}
		return internalID, version, nil
	}

	if err := transaction.database.QueryRow(
		ctx,
		insertRegistrationDeviceSQL,
		change.NodeID().String(),
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		transaction.locked.profileInternalID(),
		transaction.locked.credential.issuerInternalID,
		transaction.locked.credential.internalID,
		hostname.String(),
		change.Profile().IsEphemeral(),
		expiresAt,
		change.OccurredAt(),
	).Scan(&internalID, &version); err != nil {
		return 0, 0, fmt.Errorf("create Device: %w", err)
	}
	if internalID <= 0 || version != 1 {
		return 0, 0, ErrRegistrationEvidence
	}
	if err := transaction.persistRegistrationKeyEpochs(ctx, change, internalID); err != nil {
		return 0, 0, err
	}
	return internalID, version, nil
}

func (transaction *registrationTransaction) persistRegistrationKeyEpochs(
	ctx context.Context,
	change registration.Change,
	deviceInternalID int64,
) error {
	machineKey := change.Identity().MachineKey()
	machineKeyBytes := machineKey.Bytes()
	machineFingerprint := machineKey.Fingerprint()
	if err := transaction.execRegistrationInsert(
		ctx,
		"create machine-key epoch",
		insertRegistrationMachineKeySQL,
		change.MutationIDs().MachineKeyEpochID().String(),
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		deviceInternalID,
		machineKeyBytes[:],
		machineFingerprint[:],
		change.OccurredAt(),
	); err != nil {
		return err
	}
	nodeKey := change.Identity().NodeKey()
	nodeKeyBytes := nodeKey.Bytes()
	nodeFingerprint := nodeKey.Fingerprint()
	return transaction.execRegistrationInsert(
		ctx,
		"create Node-key epoch",
		insertRegistrationNodeKeySQL,
		change.MutationIDs().NodeKeyEpochID().String(),
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		deviceInternalID,
		nodeKeyBytes[:],
		nodeFingerprint[:],
		change.OccurredAt(),
	)
}

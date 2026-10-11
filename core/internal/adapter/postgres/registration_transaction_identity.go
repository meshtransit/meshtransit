package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
)

func (transaction *registrationTransaction) resolveCompleted(
	ctx context.Context,
	command registration.Command,
	locked registrationLockedState,
	profileID enrollment.ProfileID,
	requestHash registration.RequestHash,
) (registrationLockedState, error) {
	if !locked.pending.deviceInternalID.Valid || locked.pending.deviceInternalID.Int64 <= 0 ||
		!locked.pending.completedHostname.Valid || !locked.pending.completedDisposition.Valid ||
		!locked.pending.completedNetworkRevision.Valid {
		return registrationLockedState{}, ErrRegistrationEvidence
	}
	var nodePublicID string
	if err := transaction.database.QueryRow(
		ctx,
		lockCompletedRegistrationDeviceSQL,
		locked.pending.deviceInternalID.Int64,
	).Scan(&nodePublicID); err != nil {
		return registrationLockedState{}, fmt.Errorf("lock completed Device: %w", err)
	}
	nodeID, err := node.ParseID(nodePublicID)
	if err != nil {
		return registrationLockedState{}, ErrRegistrationEvidence
	}
	registrationValue, err := enrollment.NewRegistration(enrollment.RegistrationParams{
		ID:                 command.RegistrationID,
		Scope:              transaction.scope,
		ProfileID:          profileID,
		MachineFingerprint: command.Identity.MachineKey().Fingerprint(),
		State:              enrollment.RegistrationStateCompleted,
		NodeID:             nodeID,
		CreatedAt:          locked.pending.createdAt,
		ExpiresAt:          locked.pending.expiresAt,
	})
	if err != nil {
		return registrationLockedState{}, ErrRegistrationEvidence
	}
	hostname, err := node.ParseHostname(locked.pending.completedHostname.String)
	if err != nil {
		return registrationLockedState{}, ErrRegistrationEvidence
	}
	disposition, err := registrationDisposition(locked.pending.completedDisposition.String)
	if err != nil {
		return registrationLockedState{}, ErrRegistrationEvidence
	}
	result, err := registration.NewResult(
		command.RegistrationID,
		transaction.scope,
		nodeID,
		hostname,
		disposition,
		locked.pending.completedNetworkRevision.Int64,
	)
	if err != nil {
		return registrationLockedState{}, ErrRegistrationEvidence
	}
	resolution, err := registration.NewCompletedResolution(
		registrationValue,
		command.CredentialID,
		command.Identity,
		requestHash,
		result,
	)
	if err != nil {
		return registrationLockedState{}, ErrRegistrationEvidence
	}
	locked.resolution = resolution
	return locked, nil
}

func (transaction *registrationTransaction) resolveOpen(
	ctx context.Context,
	command registration.Command,
	locked registrationLockedState,
	registrationValue enrollment.Registration,
	profile enrollment.Profile,
	credential enrollment.Credential,
	requestHash registration.RequestHash,
) (registrationLockedState, error) {
	existingNode, err := transaction.lockExistingDevice(ctx, command, &locked)
	if err != nil {
		return registrationLockedState{}, err
	}
	if err := transaction.lockAuditHead(ctx, &locked); err != nil {
		return registrationLockedState{}, err
	}
	if err := transaction.loadHostnames(ctx, &locked, command.Hostname); err != nil {
		return registrationLockedState{}, err
	}
	if err := transaction.lockAddressState(ctx, &locked); err != nil {
		return registrationLockedState{}, err
	}
	resolution, err := registration.NewOpenResolution(
		registrationValue,
		profile,
		credential,
		existingNode,
		requestHash,
	)
	if err != nil {
		return registrationLockedState{}, ErrRegistrationEvidence
	}
	locked.resolution = resolution
	return locked, nil
}

func (transaction *registrationTransaction) lockExistingDevice(
	ctx context.Context,
	command registration.Command,
	locked *registrationLockedState,
) (node.ID, error) {
	record := &locked.device
	fingerprint := command.Identity.MachineKey().Fingerprint()
	err := transaction.database.QueryRow(ctx, lockRegistrationDeviceSQL, fingerprint[:]).Scan(
		&record.internalID,
		&record.publicID,
		&record.profileInternalID,
		&record.hostname,
		&record.version,
		&record.machineKey,
		&record.nodeKey,
		&record.hostnameLocked,
		&record.workspaceOwned,
		&record.expiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return node.ID{}, nil
	}
	if err != nil {
		return node.ID{}, fmt.Errorf("lock existing Device: %w", err)
	}
	machineKey := command.Identity.MachineKey().Bytes()
	nodeKey := command.Identity.NodeKey().Bytes()
	if record.internalID <= 0 || record.profileInternalID != locked.profileInternalID() ||
		record.version <= 0 ||
		subtle.ConstantTimeCompare(record.machineKey, machineKey[:]) != 1 ||
		subtle.ConstantTimeCompare(record.nodeKey, nodeKey[:]) != 1 {
		return node.ID{}, registration.ErrIntentConflict
	}
	nodeID, err := node.ParseID(record.publicID)
	if err != nil {
		return node.ID{}, ErrRegistrationEvidence
	}
	if _, err := node.ParseHostname(record.hostname); err != nil {
		return node.ID{}, ErrRegistrationEvidence
	}
	return nodeID, nil
}

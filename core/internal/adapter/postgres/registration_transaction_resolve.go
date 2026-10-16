package postgres

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
)

func (transaction *registrationTransaction) Resolve(
	ctx context.Context,
	command registration.Command,
) (resolution registration.Resolution, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationRegistrationResolve, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil || !command.IsValid() {
		return registration.Resolution{}, ErrRegistrationTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != registrationTransactionOpen ||
		command.Scope != transaction.scope {
		return registration.Resolution{}, ErrRegistrationTransactionState
	}

	locked, err := transaction.resolveLocked(ctx, command)
	if err != nil {
		return registration.Resolution{}, errors.Join(
			ErrResolveRegistrationTransaction,
			classifyRegistrationDatabaseError(ctx, err),
		)
	}
	transaction.locked = locked
	transaction.state = registrationTransactionResolved
	return locked.resolution, nil
}

func (transaction *registrationTransaction) resolveLocked(
	ctx context.Context,
	command registration.Command,
) (registrationLockedState, error) {
	locked := registrationLockedState{command: command}
	if err := transaction.lockPending(ctx, command, &locked); err != nil {
		return registrationLockedState{}, err
	}
	if err := transaction.lockRevision(ctx, &locked); err != nil {
		return registrationLockedState{}, err
	}
	if err := transaction.lockCredential(ctx, command, &locked); err != nil {
		return registrationLockedState{}, err
	}
	if err := transaction.lockProfile(ctx, &locked); err != nil {
		return registrationLockedState{}, err
	}
	if locked.pending.internalID <= 0 || locked.pending.intentFormatVersion != 2 ||
		locked.pending.version <= 0 {
		return registrationLockedState{}, ErrRegistrationEvidence
	}

	profile, err := locked.profile.domainValue(transaction.scope)
	if err != nil {
		return registrationLockedState{}, registrationEvidenceError("decode profile", err)
	}
	credential, err := locked.credential.domainValue(command.CredentialID, profile.ID())
	if err != nil {
		return registrationLockedState{}, registrationEvidenceError("decode credential", err)
	}
	registrationValue, err := locked.pending.domainValue(
		command.RegistrationID,
		transaction.scope,
		profile.ID(),
	)
	if err != nil && locked.pending.state != "completed" {
		return registrationLockedState{}, registrationEvidenceError("decode registration", err)
	}
	if locked.credential.profileInternalID != locked.profileInternalID() ||
		locked.pending.profileInternalID != locked.profileInternalID() ||
		!locked.pending.credentialInternalID.Valid ||
		locked.pending.credentialInternalID.Int64 != locked.credential.internalID {
		return registrationLockedState{}, ErrRegistrationEvidence
	}
	requestHash, err := registrationRequestHash(locked.pending.requestHash)
	if err != nil {
		return registrationLockedState{}, ErrRegistrationEvidence
	}
	expectedHash, err := command.RequestHash()
	if err != nil {
		return registrationLockedState{}, registration.ErrInvalidCommand
	}
	storedMachineFingerprint, err := registrationBytes32(locked.pending.machineFingerprint)
	if err != nil {
		return registrationLockedState{}, err
	}
	storedNodeKey, err := registrationBytes32(locked.pending.requestedNodeKey)
	if err != nil {
		return registrationLockedState{}, err
	}
	machineFingerprint := command.Identity.MachineKey().Fingerprint()
	nodeKey := command.Identity.NodeKey().Bytes()
	if requestHash != expectedHash ||
		subtle.ConstantTimeCompare(storedMachineFingerprint[:], machineFingerprint[:]) != 1 ||
		subtle.ConstantTimeCompare(storedNodeKey[:], nodeKey[:]) != 1 {
		return registrationLockedState{}, registration.ErrIntentConflict
	}

	if locked.pending.state == "completed" {
		return transaction.resolveCompleted(ctx, command, locked, profile.ID(), requestHash)
	}
	if !registrationValue.IsValid() ||
		(registrationValue.State() != enrollment.RegistrationStatePending &&
			registrationValue.State() != enrollment.RegistrationStateAuthorized) {
		return registrationLockedState{}, ErrRegistrationEvidence
	}
	return transaction.resolveOpen(
		ctx,
		command,
		locked,
		registrationValue,
		profile,
		credential,
		requestHash,
	)
}

func (transaction *registrationTransaction) lockRevision(
	ctx context.Context,
	locked *registrationLockedState,
) error {
	var group, policy, dns, route, sharing, isolation int64
	if err := transaction.database.QueryRow(ctx, lockRegistrationNetworkRevisionSQL).Scan(
		&locked.currentNetworkRevision,
		&locked.currentInventoryRevision,
		&group,
		&policy,
		&dns,
		&route,
		&sharing,
		&isolation,
	); err != nil {
		return fmt.Errorf("lock Network revision: %w", err)
	}
	if locked.currentNetworkRevision <= 0 || locked.currentInventoryRevision <= 0 ||
		group <= 0 || policy <= 0 || dns <= 0 || route <= 0 || sharing <= 0 || isolation <= 0 {
		return ErrRegistrationEvidence
	}
	return nil
}

func (transaction *registrationTransaction) lockCredential(
	ctx context.Context,
	command registration.Command,
	locked *registrationLockedState,
) error {
	record := &locked.credential
	if err := transaction.database.QueryRow(
		ctx,
		lockRegistrationEnrollmentAuthoritySQL,
		command.CredentialID.String(),
	).Scan(
		&record.internalID,
		&record.profileInternalID,
		&record.issuerInternalID,
		&record.issuerPublicID,
		&record.state,
		&record.useLimitKind,
		&record.maximumUses,
		&record.usedCount,
		&record.issuedRecoveryEpoch,
		&record.validFrom,
		&record.expiresAt,
		&record.version,
		&record.deviceLifetimeSeconds,
		&record.deviceNeverExpires,
	); err != nil {
		return fmt.Errorf("lock enrollment credential: %w", err)
	}
	return nil
}

func (transaction *registrationTransaction) lockProfile(
	ctx context.Context,
	locked *registrationLockedState,
) error {
	record := &locked.profile
	if err := transaction.database.QueryRow(
		ctx,
		lockRegistrationProfileSQL,
		locked.credential.profileInternalID,
	).Scan(
		&record.internalID,
		&record.publicID,
		&record.nodeLifetimeSeconds,
		&record.ephemeralMode,
		&record.useLimitKind,
		&record.maximumUses,
		&record.state,
		&record.version,
	); err != nil {
		return fmt.Errorf("lock enrollment profile: %w", err)
	}
	return nil
}

func (transaction *registrationTransaction) lockPending(
	ctx context.Context,
	command registration.Command,
	locked *registrationLockedState,
) error {
	record := &locked.pending
	if err := transaction.database.QueryRow(
		ctx,
		lockPendingRegistrationSQL,
		command.RegistrationID.String(),
	).Scan(
		&record.internalID,
		&record.profileInternalID,
		&record.credentialInternalID,
		&record.intentFormatVersion,
		&record.requestHash,
		&record.machineFingerprint,
		&record.requestedNodeKey,
		&record.deviceInternalID,
		&record.completedHostname,
		&record.completedDisposition,
		&record.completedNetworkRevision,
		&record.state,
		&record.version,
		&record.createdAt,
		&record.expiresAt,
	); err != nil {
		return fmt.Errorf("lock pending registration: %w", err)
	}
	return nil
}

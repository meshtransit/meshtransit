package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
)

func (transaction *registrationTransaction) Apply(
	ctx context.Context,
	change registration.Change,
) (result registration.Result, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationRegistrationApply, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil || !change.IsValid() {
		return registration.Result{}, ErrRegistrationTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	// The change decides on this transaction's database time only.
	if transaction.database == nil || transaction.state != registrationTransactionResolved ||
		!change.OccurredAt().Equal(transaction.decisionAt) ||
		!transaction.changeMatchesLockedState(change) {
		return registration.Result{}, ErrRegistrationTransactionState
	}

	result, err := transaction.applyLocked(ctx, change)
	if err != nil {
		return registration.Result{}, errors.Join(
			ErrApplyRegistrationTransaction,
			classifyRegistrationDatabaseError(ctx, err),
		)
	}
	transaction.state = registrationTransactionApplied
	return result, nil
}

func (transaction *registrationTransaction) changeMatchesLockedState(
	change registration.Change,
) bool {
	locked := transaction.locked
	resolution := locked.resolution
	if _, completed := resolution.CompletedResult(); completed {
		return false
	}
	registrationBefore := resolution.Registration()
	registrationAfter := change.Registration()
	credentialBefore := resolution.Credential()
	credentialAfter := change.Credential()
	if !registrationBefore.IsValid() || !registrationAfter.IsValid() ||
		registrationAfter.State() != enrollment.RegistrationStateCompleted ||
		registrationBefore.ID() != registrationAfter.ID() ||
		registrationBefore.Scope() != registrationAfter.Scope() ||
		registrationBefore.ProfileID() != registrationAfter.ProfileID() ||
		registrationBefore.MachineFingerprint() != registrationAfter.MachineFingerprint() ||
		!registrationBefore.CreatedAt().Equal(registrationAfter.CreatedAt()) ||
		!registrationBefore.ExpiresAt().Equal(registrationAfter.ExpiresAt()) ||
		change.Profile() != resolution.Profile() || change.Identity() != locked.command.Identity ||
		change.Hostname() != locked.command.Hostname ||
		credentialAfter.ID() != credentialBefore.ID() ||
		credentialAfter.ProfileID() != credentialBefore.ProfileID() ||
		credentialAfter.IssuerID() != credentialBefore.IssuerID() ||
		credentialAfter.State() != credentialBefore.State() ||
		credentialAfter.UseLimit() != credentialBefore.UseLimit() ||
		credentialAfter.IssuedRecoveryEpoch() != credentialBefore.IssuedRecoveryEpoch() ||
		!credentialAfter.ValidFrom().Equal(credentialBefore.ValidFrom()) ||
		!credentialAfter.ExpiresAt().Equal(credentialBefore.ExpiresAt()) ||
		credentialAfter.UsedCount() != credentialBefore.UsedCount()+1 ||
		change.OwnerID() != credentialBefore.IssuerID() ||
		change.CustodianID() != credentialBefore.IssuerID() ||
		registrationAfter.Scope() != transaction.scope {
		return false
	}

	existingNode, exists := resolution.ExistingNodeID()
	switch change.Disposition() {
	case registration.DispositionCreated:
		return !exists && locked.device.internalID == 0
	case registration.DispositionResumed:
		return exists && locked.device.internalID > 0 && existingNode == change.NodeID()
	default:
		return false
	}
}

func (transaction *registrationTransaction) applyLocked(
	ctx context.Context,
	change registration.Change,
) (registration.Result, error) {
	hostname := transaction.locked.hostname
	if !hostname.IsValid() {
		return registration.Result{}, ErrRegistrationAllocation
	}
	var err error
	expiresAt, err := change.Profile().DeviceExpiresAtFor(change.Credential(), change.OccurredAt())
	if err != nil {
		return registration.Result{}, err
	}
	// A resumed Device keeps an administrator's rename and, when the
	// Workspace owns it, its never-expiring lifetime (schema 125).
	if existing := transaction.locked.device; change.Disposition() == registration.DispositionResumed {
		if existing.hostnameLocked {
			if hostname, err = node.ParseHostname(existing.hostname); err != nil {
				return registration.Result{}, ErrRegistrationEvidence
			}
		}
		if existing.workspaceOwned {
			expiresAt = existing.expiresAt
		}
	}
	leases, err := transaction.allocateRegistrationLeases()
	if err != nil {
		return registration.Result{}, err
	}

	if _, err := transaction.database.Exec(
		ctx,
		setRegistrationChangeSQL,
		change.MutationIDs().ChangeID().String(),
	); err != nil {
		return registration.Result{}, fmt.Errorf("set authority change context: %w", err)
	}

	deviceInternalID, deviceVersion, err := transaction.persistRegistrationDevice(
		ctx,
		change,
		hostname,
		expiresAt,
	)
	if err != nil {
		return registration.Result{}, err
	}
	if err := transaction.persistCredentialConsumption(ctx, change); err != nil {
		return registration.Result{}, err
	}
	if err := transaction.persistCredentialUse(ctx, change, deviceInternalID); err != nil {
		return registration.Result{}, err
	}
	if err := transaction.persistRegistrationLeases(ctx, change, deviceInternalID, leases); err != nil {
		return registration.Result{}, err
	}

	networkRevision, inventoryRevision, err := transaction.advanceRegistrationRevision(ctx)
	if err != nil {
		return registration.Result{}, err
	}
	if err := transaction.completePendingRegistration(
		ctx,
		change,
		deviceInternalID,
		hostname,
		networkRevision,
	); err != nil {
		return registration.Result{}, err
	}
	if err := transaction.appendRegistrationEvidence(
		ctx,
		change,
		hostname,
		deviceVersion,
		networkRevision,
		inventoryRevision,
		expiresAt,
	); err != nil {
		return registration.Result{}, err
	}

	result, err := registration.NewResult(
		change.Registration().ID(),
		transaction.scope,
		change.NodeID(),
		hostname,
		change.Disposition(),
		networkRevision,
	)
	if err != nil {
		return registration.Result{}, ErrRegistrationEvidence
	}
	return result, nil
}

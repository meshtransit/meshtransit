package registrationintake

import (
	"context"
	"errors"
	"fmt"
	"time"

	appintake "github.com/meshtransit/meshtransit/internal/enrollment/registration/intake"
)

func (transaction *transaction) Apply(
	ctx context.Context,
	change appintake.Change,
) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		if transaction != nil {
			observe(transaction.observer, OperationApply, startedAt, resultErr)
		}
	}()
	if ctx == nil || transaction == nil || !change.IsValid() {
		return ErrTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != transactionResolved ||
		!transaction.changeMatchesResolution(change) {
		return ErrTransactionState
	}

	if err := transaction.applyLocked(ctx, change); err != nil {
		return errors.Join(ErrApplyTransaction, classifyDatabaseError(ctx, err))
	}
	transaction.state = transactionApplied
	return nil
}

func (transaction *transaction) changeMatchesResolution(change appintake.Change) bool {
	command := change.Command()
	if command.Scope != transaction.scope || command.RegistrationID != transaction.lookup.RegistrationID ||
		command.CredentialID != transaction.lookup.CredentialID ||
		command.Identity.MachineKey().Fingerprint() != transaction.lookup.MachineFingerprint ||
		command.RecoveryEpoch != transaction.recoveryEpoch {
		return false
	}
	authority := transaction.locked.resolution.Authority()
	_, _, existing := transaction.locked.resolution.ExistingIntent()
	return !existing && authority.IsValid() && authority.Scope() == transaction.scope &&
		authority.Credential().ID() == command.CredentialID &&
		authority.Profile().ID() == change.Registration().ProfileID()
}

func (transaction *transaction) applyLocked(
	ctx context.Context,
	change appintake.Change,
) error {
	if err := transaction.lockAuditHead(ctx); err != nil {
		return err
	}
	if _, err := transaction.database.Exec(
		ctx,
		setChangeIDSQL,
		change.EvidenceIDs().ChangeID().String(),
	); err != nil {
		return fmt.Errorf("set authority change context: %w", err)
	}
	command := change.Command()
	machineFingerprint := command.Identity.MachineKey().Fingerprint()
	nodeKey := command.Identity.NodeKey().Bytes()
	requestHash := change.RequestHash().Bytes()
	var internalID, version int64
	if err := transaction.database.QueryRow(
		ctx,
		insertIntentSQL,
		command.RegistrationID.String(),
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		transaction.locked.profileInternalID,
		"credential",
		transaction.locked.credentialInternalID,
		machineFingerprint[:],
		change.Registration().ExpiresAt(),
		requestHash[:],
		nodeKey[:],
		change.OccurredAt(),
		change.OccurredAt(),
	).Scan(&internalID, &version); err != nil {
		return fmt.Errorf("insert pending registration intent: %w", err)
	}
	if internalID <= 0 || version != 1 {
		return ErrEvidence
	}
	if err := transaction.appendEvidence(ctx, change, version); err != nil {
		return err
	}
	return nil
}

func (transaction *transaction) lockAuditHead(ctx context.Context) error {
	var previousHash []byte
	if err := transaction.database.QueryRow(ctx, lockAuditHeadSQL).Scan(
		&transaction.locked.audit.streamInternalID,
		&transaction.locked.audit.nextSequence,
		&previousHash,
	); err != nil {
		return fmt.Errorf("lock audit stream: %w", err)
	}
	if transaction.locked.audit.streamInternalID <= 0 ||
		transaction.locked.audit.nextSequence <= 0 || len(previousHash) != 32 {
		return ErrEvidence
	}
	copy(transaction.locked.audit.previousHash[:], previousHash)
	return nil
}

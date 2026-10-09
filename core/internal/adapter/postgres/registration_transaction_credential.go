package postgres

import (
	"context"
	"fmt"

	"meshtransit.net/core/internal/domain/enrollment/registration"
)

func (transaction *registrationTransaction) persistCredentialConsumption(
	ctx context.Context,
	change registration.Change,
) error {
	result, err := transaction.database.Exec(
		ctx,
		consumeRegistrationEnrollmentAuthoritySQL,
		transaction.locked.credential.internalID,
		change.Credential().UsedCount(),
		change.OccurredAt(),
		transaction.locked.credential.usedCount,
		transaction.locked.credential.version,
	)
	if err != nil {
		return fmt.Errorf("consume enrollment credential: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrRegistrationEvidence
	}
	return nil
}

func (transaction *registrationTransaction) persistCredentialUse(
	ctx context.Context,
	change registration.Change,
	deviceInternalID int64,
) error {
	fingerprint := change.Identity().MachineKey().Fingerprint()
	return transaction.execRegistrationInsert(
		ctx,
		"append enrollment credential use",
		insertRegistrationCredentialUseSQL,
		change.MutationIDs().CredentialUseID().String(),
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		transaction.locked.credential.internalID,
		transaction.locked.pending.internalID,
		deviceInternalID,
		fingerprint[:],
		registrationDispositionValue(change.Disposition()),
		change.OccurredAt(),
	)
}

func (transaction *registrationTransaction) execRegistrationInsert(
	ctx context.Context,
	operation string,
	query string,
	arguments ...any,
) error {
	result, err := transaction.database.Exec(ctx, query, arguments...)
	if err != nil {
		return fmt.Errorf("%s: %w", operation, err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("%s: %w", operation, ErrRegistrationEvidence)
	}
	return nil
}

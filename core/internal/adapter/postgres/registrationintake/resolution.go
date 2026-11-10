package registrationintake

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	appintake "meshtransit.net/core/internal/domain/enrollment/registration/intake"
)

func (transaction *transaction) Resolve(
	ctx context.Context,
	lookup appintake.Lookup,
) (resolution appintake.Resolution, resultErr error) {
	startedAt := time.Now()
	defer func() {
		if transaction != nil {
			observe(transaction.observer, OperationResolve, startedAt, resultErr)
		}
	}()
	if ctx == nil || transaction == nil || !lookup.IsValid() {
		resultErr = ErrTransactionState
		return appintake.Resolution{}, resultErr
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != transactionOpen ||
		lookup != transaction.lookup {
		resultErr = ErrTransactionState
		return appintake.Resolution{}, resultErr
	}

	locked, err := transaction.resolveLocked(ctx, lookup)
	if err != nil {
		resultErr = errors.Join(
			ErrResolveTransaction,
			classifyDatabaseError(ctx, err),
		)
		return appintake.Resolution{}, resultErr
	}
	transaction.locked = locked
	transaction.state = transactionResolved
	return locked.resolution, resultErr
}

// boundToAnotherOwner reports whether the machine key already holds a
// member's Device in this Network that the key's issuer does not own
// (TD-SEC-75). The registration transaction refuses such a key too, but the
// service refuses it first, once the key is authenticated, so no pending
// intent is left to block the owner's own key.
func (transaction *transaction) boundToAnotherOwner(ctx context.Context, lookup appintake.Lookup,
	issuer int64) (bool, error) {
	var owner int64
	var workspaceOwned, signedOut bool
	err := transaction.database.QueryRow(ctx, readBoundDeviceOwnerSQL, lookup.MachineFingerprint[:]).
		Scan(&owner, &workspaceOwned, &signedOut)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read the machine key's Device: %w", err)
	}
	// A signed-out Device reopens only by its owner signing in (schema 283).
	return signedOut || (!workspaceOwned && owner != issuer), nil
}

func (transaction *transaction) resolveLocked(
	ctx context.Context,
	lookup appintake.Lookup,
) (lockedState, error) {
	intent, err := transaction.lockIntents(ctx, lookup)
	if err != nil {
		return lockedState{}, err
	}
	currentRevision, err := transaction.lockRevision(ctx)
	if err != nil {
		return lockedState{}, err
	}
	credentialRecord, err := transaction.lockCredential(ctx, lookup.CredentialID)
	if err != nil {
		return lockedState{}, err
	}
	foreign, err := transaction.boundToAnotherOwner(ctx, lookup, credentialRecord.issuerInternalID)
	if err != nil {
		return lockedState{}, err
	}
	digest, err := transaction.loadDigest(ctx, lookup.CredentialID)
	if err != nil {
		return lockedState{}, err
	}
	profileRecord, err := transaction.lockProfile(ctx, credentialRecord.profileInternalID)
	if err != nil {
		return lockedState{}, err
	}
	if credentialRecord.profileInternalID != profileRecord.internalID {
		return lockedState{}, ErrEvidence
	}
	profile, err := profileRecord.domainValue(transaction.scope)
	if err != nil {
		return lockedState{}, err
	}
	credential, err := credentialRecord.domainValue(lookup.CredentialID, profile.ID())
	if err != nil {
		return lockedState{}, err
	}
	authority, err := appintake.NewAuthority(appintake.AuthorityParams{
		DeploymentID:  transaction.deploymentID,
		Scope:         transaction.scope,
		Profile:       profile,
		Credential:    credential,
		Digest:        digest,
		RecoveryEpoch: transaction.recoveryEpoch,
	})
	if err != nil {
		return lockedState{}, ErrEvidence
	}
	resolution := appintake.NewResolution(authority)
	if intent.exists {
		resolution, err = appintake.NewExistingResolution(
			authority,
			intent.registrationID,
			intent.requestHash,
		)
		if err != nil {
			return lockedState{}, ErrEvidence
		}
	}
	if foreign {
		resolution = resolution.WithForeignDevice()
	}
	return lockedState{
		resolution:             resolution,
		credentialInternalID:   credentialRecord.internalID,
		profileInternalID:      profileRecord.internalID,
		issuerPublicID:         credentialRecord.issuerPublicID,
		currentNetworkRevision: currentRevision,
	}, nil
}

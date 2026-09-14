package registrationintake

import (
	"context"
	"errors"
	"time"

	appintake "github.com/meshtransit/meshtransit/internal/enrollment/registration/intake"
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
	return lockedState{
		resolution:             resolution,
		credentialInternalID:   credentialRecord.internalID,
		profileInternalID:      profileRecord.internalID,
		issuerPublicID:         credentialRecord.issuerPublicID,
		currentNetworkRevision: currentRevision,
	}, nil
}

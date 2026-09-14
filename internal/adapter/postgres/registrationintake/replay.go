package registrationintake

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
)

// ResolvePrepared verifies durable semantic evidence after an uncertain commit.
func (transactions *Transactions) ResolvePrepared(
	ctx context.Context,
	command registration.Command,
) (_ registration.RequestHash, _ bool, resultErr error) {
	if ctx == nil || transactions == nil || transactions.database == nil ||
		!validOptions(transactions.options) || !command.IsValid() {
		return registration.RequestHash{}, false, ErrResolvePrepared
	}
	startedAt := time.Now()
	defer func() {
		observe(transactions.observer, OperationReplay, startedAt, resultErr)
	}()
	databaseTransaction, err := transactions.database.Begin(ctx)
	if err != nil {
		return registration.RequestHash{}, false, errors.Join(
			ErrResolvePrepared,
			classifyDatabaseError(ctx, err),
		)
	}
	defer func() {
		resultErr = errors.Join(resultErr, rollbackSetup(databaseTransaction))
	}()
	if err := configure(ctx, databaseTransaction, transactions.options); err != nil {
		return registration.RequestHash{}, false, errors.Join(
			ErrResolvePrepared,
			classifyDatabaseError(ctx, err),
		)
	}
	var workspaceInternalID, networkInternalID int64
	if err := databaseTransaction.QueryRow(
		ctx,
		setScopeSQL,
		command.Scope.WorkspaceID().String(),
		command.Scope.NetworkID().String(),
	).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return registration.RequestHash{}, false, errors.Join(
			ErrResolvePrepared,
			classifyDatabaseError(ctx, err),
		)
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return registration.RequestHash{}, false, errors.Join(ErrResolvePrepared, ErrEvidence)
	}

	var requestHashBytes, machineFingerprint, nodeKey []byte
	var credentialID string
	var intentFormatVersion int16
	var state string
	var version int64
	err = databaseTransaction.QueryRow(
		ctx,
		loadPreparedIntentSQL,
		command.RegistrationID.String(),
	).Scan(
		&requestHashBytes,
		&credentialID,
		&machineFingerprint,
		&nodeKey,
		&intentFormatVersion,
		&state,
		&version,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return registration.RequestHash{}, false, nil
	}
	if err != nil {
		return registration.RequestHash{}, false, errors.Join(
			ErrResolvePrepared,
			classifyDatabaseError(ctx, err),
		)
	}
	requestHash, err := validatePreparedEvidence(
		command,
		requestHashBytes,
		credentialID,
		machineFingerprint,
		nodeKey,
		intentFormatVersion,
		state,
		version,
	)
	if err != nil {
		return registration.RequestHash{}, false, errors.Join(ErrResolvePrepared, err)
	}
	return requestHash, true, nil
}

func validatePreparedEvidence(
	command registration.Command,
	requestHashBytes []byte,
	credentialIDValue string,
	machineFingerprintBytes []byte,
	nodeKeyBytes []byte,
	intentFormatVersion int16,
	state string,
	version int64,
) (registration.RequestHash, error) {
	credentialID, err := enrollment.ParseCredentialID(credentialIDValue)
	if err != nil || credentialID != command.CredentialID || intentFormatVersion != 2 ||
		version <= 0 || !validIntentState(state) {
		return registration.RequestHash{}, ErrEvidence
	}
	requestHash, err := requestHashValue(requestHashBytes)
	if err != nil {
		return registration.RequestHash{}, err
	}
	machineFingerprint, err := bytes32(machineFingerprintBytes)
	if err != nil {
		return registration.RequestHash{}, err
	}
	nodeKey, err := bytes32(nodeKeyBytes)
	if err != nil {
		return registration.RequestHash{}, err
	}
	expectedMachineFingerprint := command.Identity.MachineKey().Fingerprint()
	expectedNodeKey := command.Identity.NodeKey().Bytes()
	expectedHash, err := command.RequestHash()
	if err != nil {
		return registration.RequestHash{}, ErrEvidence
	}
	if subtle.ConstantTimeCompare(machineFingerprint[:], expectedMachineFingerprint[:]) != 1 ||
		subtle.ConstantTimeCompare(nodeKey[:], expectedNodeKey[:]) != 1 || requestHash != expectedHash {
		return registration.RequestHash{}, ErrEvidence
	}
	return requestHash, nil
}

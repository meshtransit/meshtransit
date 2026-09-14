package registrationintake

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"fmt"

	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
	appintake "github.com/meshtransit/meshtransit/internal/enrollment/registration/intake"
)

type intentRecord struct {
	internalID           int64
	registrationID       enrollment.RegistrationID
	credentialInternalID int64
	requestHash          registration.RequestHash
	machineFingerprint   [32]byte
	nodeKey              [32]byte
	state                string
	version              int64
	exists               bool
}

func (transaction *transaction) lockIntents(
	ctx context.Context,
	lookup appintake.Lookup,
) (intentRecord, error) {
	rows, err := transaction.database.Query(
		ctx,
		lockIntentsSQL,
		lookup.RegistrationID.String(),
		lookup.MachineFingerprint[:],
	)
	if err != nil {
		return intentRecord{}, fmt.Errorf("lock pending registration intents: %w", err)
	}
	defer rows.Close()

	var selected intentRecord
	count := 0
	for rows.Next() {
		count++
		if count > 2 {
			return intentRecord{}, ErrEvidence
		}
		record, err := scanIntent(rows)
		if err != nil {
			return intentRecord{}, err
		}
		isExactID := record.registrationID == lookup.RegistrationID
		isActiveMachine := (record.state == "pending" || record.state == "authorized") &&
			subtle.ConstantTimeCompare(
				record.machineFingerprint[:],
				lookup.MachineFingerprint[:],
			) == 1
		if !isExactID && !isActiveMachine {
			return intentRecord{}, ErrEvidence
		}
		if !selected.exists || isExactID {
			selected = record
		}
	}
	if err := rows.Err(); err != nil {
		return intentRecord{}, fmt.Errorf("read pending registration intents: %w", err)
	}
	return selected, nil
}

func scanIntent(row interface{ Scan(...any) error }) (intentRecord, error) {
	var record intentRecord
	var publicID string
	var credentialInternalID sql.NullInt64
	var intentFormatVersion int16
	var requestHash, machineFingerprint, nodeKey []byte
	if err := row.Scan(
		&record.internalID,
		&publicID,
		&credentialInternalID,
		&intentFormatVersion,
		&requestHash,
		&machineFingerprint,
		&nodeKey,
		&record.state,
		&record.version,
	); err != nil {
		return intentRecord{}, fmt.Errorf("scan pending registration intent: %w", err)
	}
	registrationID, err := enrollment.ParseRegistrationID(publicID)
	if err != nil || record.internalID <= 0 || !credentialInternalID.Valid ||
		credentialInternalID.Int64 <= 0 || intentFormatVersion != 2 || record.version <= 0 ||
		!validIntentState(record.state) {
		return intentRecord{}, ErrEvidence
	}
	record.registrationID = registrationID
	record.credentialInternalID = credentialInternalID.Int64
	record.requestHash, err = requestHashValue(requestHash)
	if err != nil {
		return intentRecord{}, err
	}
	record.machineFingerprint, err = bytes32(machineFingerprint)
	if err != nil {
		return intentRecord{}, err
	}
	record.nodeKey, err = bytes32(nodeKey)
	if err != nil {
		return intentRecord{}, err
	}
	record.exists = true
	return record, nil
}

func requestHashValue(value []byte) (registration.RequestHash, error) {
	if len(value) != 32 {
		return registration.RequestHash{}, ErrEvidence
	}
	var hash [32]byte
	copy(hash[:], value)
	result, err := registration.NewRequestHash(hash)
	if err != nil {
		return registration.RequestHash{}, ErrEvidence
	}
	return result, nil
}

func bytes32(value []byte) ([32]byte, error) {
	if len(value) != 32 {
		return [32]byte{}, ErrEvidence
	}
	var result [32]byte
	copy(result[:], value)
	if result == ([32]byte{}) {
		return [32]byte{}, ErrEvidence
	}
	return result, nil
}

func validIntentState(value string) bool {
	switch value {
	case "pending", "authorized", "completed", "rejected", "expired":
		return true
	default:
		return false
	}
}

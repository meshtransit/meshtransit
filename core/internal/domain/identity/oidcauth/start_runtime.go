package oidcauth

import (
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/publicid"
)

// SystemStartIDs creates public transaction and evidence IDs with OS entropy.
type SystemStartIDs struct{}

// NewStartIDs generates exactly one distinct UUIDv7 set before database work.
func (SystemStartIDs) NewStartIDs() (TransactionID, MutationIDs, error) {
	var values [4]publicid.ID
	for index := range values {
		value, err := publicid.New()
		if err != nil {
			return TransactionID{}, MutationIDs{}, err
		}
		values[index] = value
	}
	transactionID := TransactionID(values[0])
	ids, err := NewMutationIDs(MutationIDParams{
		ChangeID: values[1], AuditEventID: values[2], OutboxEventID: values[3],
	})
	if err != nil {
		return TransactionID{}, MutationIDs{}, err
	}
	for _, value := range values[1:] {
		if value == values[0] {
			return TransactionID{}, MutationIDs{}, ErrInvalidMutationIDs
		}
	}
	return transactionID, ids, nil
}

// SystemSecrets uses the operating-system CSPRNG, not a shared pseudo-random stream.
type SystemSecrets struct{}

// NewSecrets generates independent state, nonce, PKCE verifier, and pre-auth cookie material.
func (SystemSecrets) NewSecrets() (Secrets, error) { return GenerateSecrets() }

// SystemStartClock reads UTC wall time without retaining request state.
type SystemStartClock struct{}

// Now returns the current UTC time.
func (SystemStartClock) Now() time.Time { return time.Now().UTC() }

var (
	_ StartIDGenerator = SystemStartIDs{}
	_ SecretsGenerator = SystemSecrets{}
	_ StartClock       = SystemStartClock{}
)

// StartOutcome is a closed, secret-free telemetry category.
type StartOutcome uint8

const (
	// StartOutcomeUnknown is invalid or unsupported telemetry evidence.
	StartOutcomeUnknown StartOutcome = iota
	// StartOutcomeCommitted means a durable, live redirect was released.
	StartOutcomeCommitted
	// StartOutcomeRejected means malformed or stale creation evidence.
	StartOutcomeRejected
	// StartOutcomeUnavailable means cancellation or a dependency failure.
	StartOutcomeUnavailable
	// StartOutcomeUncertain means no exact durable commit could be confirmed.
	StartOutcomeUncertain
	// StartOutcomeCleanupFailed means owned transaction cleanup failed.
	StartOutcomeCleanupFailed
)

// String maps every outcome to a bounded label, including unknown numeric values.
func (outcome StartOutcome) String() string {
	switch outcome {
	case StartOutcomeCommitted:
		return "committed"
	case StartOutcomeRejected:
		return "rejected"
	case StartOutcomeUnavailable:
		return "unavailable"
	case StartOutcomeUncertain:
		return "uncertain"
	case StartOutcomeCleanupFailed:
		return "cleanup_failed"
	default:
		return "unknown"
	}
}

func startOutcome(err error) StartOutcome {
	switch {
	case err == nil:
		return StartOutcomeCommitted
	case errors.Is(err, ErrStartRollbackFailed):
		return StartOutcomeCleanupFailed
	case errors.Is(err, ErrCommitOutcomeUnknown):
		return StartOutcomeUncertain
	case errors.Is(err, ErrInvalidRoute), errors.Is(err, ErrInvalidPending),
		errors.Is(err, ErrInvalidCreated), errors.Is(err, ErrStartExpired),
		errors.Is(err, ErrProviderMismatch), errors.Is(err, ErrUnsupportedProvider):
		return StartOutcomeRejected
	default:
		return StartOutcomeUnavailable
	}
}

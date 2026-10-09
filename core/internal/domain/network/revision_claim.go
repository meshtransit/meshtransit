package network

import (
	"errors"
	"time"
)

// ErrInvalidRevisionClaim indicates malformed durable outbox claim metadata.
var ErrInvalidRevisionClaim = errors.New("invalid network revision claim")

// RevisionClaim is the immutable fencing handle for one claimed durable
// Network-revision outbox event. Internal database IDs never leave the process.
type RevisionClaim struct {
	eventID          int64
	workspaceID      int64
	networkID        int64
	recordedRevision int64
	token            string
	workerID         string
	attempt          int
	claimedAt        time.Time
}

// NewRevisionClaim validates durable claim metadata returned by PostgreSQL.
func NewRevisionClaim(
	eventID int64,
	workspaceID int64,
	networkID int64,
	recordedRevision int64,
	token string,
	workerID string,
	attempt int,
	claimedAt time.Time,
) (RevisionClaim, error) {
	if eventID <= 0 || workspaceID <= 0 || networkID <= 0 || recordedRevision <= 0 ||
		!validCanonicalUUID(token) || !validWorkerID(workerID) || attempt <= 0 || claimedAt.IsZero() {
		return RevisionClaim{}, ErrInvalidRevisionClaim
	}
	return RevisionClaim{
		eventID:          eventID,
		workspaceID:      workspaceID,
		networkID:        networkID,
		recordedRevision: recordedRevision,
		token:            token,
		workerID:         workerID,
		attempt:          attempt,
		claimedAt:        claimedAt,
	}, nil
}

// EventID returns the internal outbox row identity.
func (claim RevisionClaim) EventID() int64 { return claim.eventID }

// WorkspaceID returns the internal scope used only for transaction-local RLS.
func (claim RevisionClaim) WorkspaceID() int64 { return claim.workspaceID }

// NetworkID returns the internal scope used only for transaction-local RLS.
func (claim RevisionClaim) NetworkID() int64 { return claim.networkID }

// RecordedRevision returns the revision committed with the outbox event.
func (claim RevisionClaim) RecordedRevision() int64 { return claim.recordedRevision }

// Token returns the opaque fencing token for this lease.
func (claim RevisionClaim) Token() string { return claim.token }

// WorkerID returns the bounded worker identity that owns this lease.
func (claim RevisionClaim) WorkerID() string { return claim.workerID }

// Attempt returns the durable one-based delivery attempt number.
func (claim RevisionClaim) Attempt() int { return claim.attempt }

// ClaimedAt returns the database-recorded start time for this attempt.
func (claim RevisionClaim) ClaimedAt() time.Time { return claim.claimedAt }

// IsValid reports whether the claim preserves its construction invariants.
func (claim RevisionClaim) IsValid() bool {
	return claim.eventID > 0 && claim.workspaceID > 0 && claim.networkID > 0 &&
		claim.recordedRevision > 0 && validCanonicalUUID(claim.token) &&
		validWorkerID(claim.workerID) && claim.attempt > 0 && !claim.claimedAt.IsZero()
}

func validCanonicalUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' ||
		value[18] != '-' || value[23] != '-' {
		return false
	}
	version := value[14]
	if version < '1' || version > '8' {
		return false
	}
	variant := value[19]
	if variant != '8' && variant != '9' && variant != 'a' && variant != 'b' {
		return false
	}
	for index := range len(value) {
		switch index {
		case 8, 13, 18, 23:
			continue
		}
		character := value[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validWorkerID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == '_' || character == ':' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

package postgres

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node/keyrotation"
)

// Schema 281: a write that reaches a deleted Network ends for good.
func TestDeletedNetworkEndsRegistrationAndRotation(t *testing.T) {
	t.Parallel()
	deleted := &pgconn.PgError{Code: "MTN02"}
	if err := classifyRegistrationDatabaseError(t.Context(), deleted); !errors.Is(err, registration.ErrRegistrationFailed) ||
		errors.Is(err, registration.ErrRetryableTransaction) {
		t.Fatalf("registration: %v", err)
	}
	if err := classifyNodeKeyRotationDatabaseError(t.Context(), deleted); !errors.Is(err, keyrotation.ErrNotFound) {
		t.Fatalf("key rotation: %v", err)
	}
}

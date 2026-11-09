package registrationintake

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	appintake "meshtransit.net/core/internal/domain/enrollment/registration/intake"
)

// Schema 281: intake for a deleted Network rejects the credential.
func TestDeletedNetworkRejectsIntake(t *testing.T) {
	t.Parallel()
	if err := classifyDatabaseError(t.Context(), &pgconn.PgError{Code: "MTN02"}); !errors.Is(err, appintake.ErrCredentialRejected) {
		t.Fatalf("intake: %v", err)
	}
}

package postgres

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

func TestAuthTransactionCommitClassificationUsesDomainUnknownSeam(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name        string
		err         error
		wantUnknown bool
	}{
		{name: "transport", err: io.EOF, wantUnknown: true},
		{name: "canceled transport", err: context.Canceled, wantUnknown: true},
		{name: "postgres rejected", err: &pgconn.PgError{Code: "23514"}},
		{name: "postgres aborted", err: pgx.ErrTxCommitRollback},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := classifyAuthTransactionCommitError(t.Context(), test.err)
			if errors.Is(err, oidcauth.ErrCommitOutcomeUnknown) != test.wantUnknown ||
				errors.Is(err, ErrAuthTransactionCommitOutcomeUnknown) != test.wantUnknown {
				t.Fatalf("commit classification = %v, want unknown=%t", err, test.wantUnknown)
			}
		})
	}
}

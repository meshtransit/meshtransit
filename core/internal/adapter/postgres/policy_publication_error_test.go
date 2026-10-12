package postgres

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	publication "meshtransit.net/core/internal/domain/policy/publication"
)

func TestClassifyPolicyPublicationDatabaseError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		code string
		want error
	}{
		{code: "MT001", want: publication.ErrConflict},
		{code: "MTD06", want: publication.ErrEdgeBudget},
		{code: "MTP05", want: publication.ErrDeviceUnavailable},
		{code: "40001", want: publication.ErrRetryableTransaction},
	}
	for _, test := range tests {
		t.Run(test.code, func(t *testing.T) {
			t.Parallel()
			err := classifyPolicyPublicationDatabaseError(t.Context(), &pgconn.PgError{Code: test.code})
			if !errors.Is(err, test.want) {
				t.Fatalf("classify(%s) = %v, want %v", test.code, err, test.want)
			}
		})
	}

	unclassified := classifyPolicyPublicationDatabaseError(t.Context(), &pgconn.PgError{Code: "23514"})
	if errors.Is(unclassified, publication.ErrDeviceUnavailable) ||
		errors.Is(unclassified, publication.ErrConflict) {
		t.Fatalf("classify(23514) = %v, want an unclassified failure", unclassified)
	}
}

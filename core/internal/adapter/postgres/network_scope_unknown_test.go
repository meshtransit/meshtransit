package postgres

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestUnknownNetworkScope(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{"the scope refusal", &pgconn.PgError{Code: "23503", Message: "network scope is unavailable"}, true},
		{"wrapped", fmt.Errorf("scope: %w", &pgconn.PgError{Code: "23503", Message: "network scope is unavailable"}), true},
		{"another foreign key", &pgconn.PgError{Code: "23503", Message: "insert or update violates foreign key"}, false},
		{"scope replaced", &pgconn.PgError{Code: "42501", Message: "transaction Network scope cannot be replaced"}, false},
		{"not PostgreSQL", errors.New("network scope is unavailable"), false},
		{"nil", nil, false},
	} {
		if got := unknownNetworkScope(test.err); got != test.want {
			t.Errorf("%s: unknownNetworkScope() = %v, want %v", test.name, got, test.want)
		}
	}
}

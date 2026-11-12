package postgres

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/enrollment/registration"
)

// TD-CORE-150: keys that hold a Device in another Network or Workspace are
// invisible to the resume lookup (Network scope) and surface as a unique
// violation on the global key indexes. That is a lasting refusal; any other
// error stays as it was, to be retried.
func TestKeysHeldElsewhereNamesOnlyTheKeyIndexes(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		err        error
		refusedFor bool
	}{
		{"machine key held", &pgconn.PgError{Code: "23505", ConstraintName: "device_machine_key_epoch_key_active_uidx"}, true},
		{"node key held", &pgconn.PgError{Code: "23505", ConstraintName: "device_node_key_epoch_key_active_uidx"}, true},
		{"node key used before", &pgconn.PgError{Code: "23505", ConstraintName: "device_node_key_epoch_key_history_uidx"}, true},
		{"another unique index", &pgconn.PgError{Code: "23505", ConstraintName: "device_network_hostname_active_uidx"}, false},
		{"lock timeout", &pgconn.PgError{Code: "55P03", ConstraintName: "device_machine_key_epoch_key_active_uidx"}, false},
		{"not a database error", errors.New("connection reset"), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := keysHeldElsewhere(test.err)
			if refused := errors.Is(got, registration.ErrKeysHeldElsewhere); refused != test.refusedFor {
				t.Fatalf("keysHeldElsewhere(%v) = %v, refused %t, want %t", test.err, got, refused, test.refusedFor)
			}
			if !test.refusedFor && got != test.err {
				t.Fatalf("keysHeldElsewhere(%v) = %v, want the error unchanged", test.err, got)
			}
		})
	}
}

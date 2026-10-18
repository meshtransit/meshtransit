package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	authority "meshtransit.net/core/internal/domain/resource/authority"
)

func TestResourceAuthorityDatabaseErrorNamesUniqueViolations(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, code, constraint string
		want, not              error
	}{
		{name: "name taken", code: "23505", constraint: "resource_network_name_current_uidx",
			want: authority.ErrNameTaken, not: authority.ErrConflict},
		{name: "Device has a Resource", code: "23505", constraint: "resource_device_target_active_device_uidx",
			want: authority.ErrDeviceResourceExists, not: authority.ErrConflict},
		{name: "other unique violation", code: "23505", constraint: "resource_public_id_key",
			want: authority.ErrConflict, not: authority.ErrNameTaken},
		{name: "stale revision", code: "MT001", want: authority.ErrConflict, not: authority.ErrNameTaken},
	} {
		err := classifyResourceAuthorityDatabaseError(context.Background(),
			&pgconn.PgError{Code: test.code, ConstraintName: test.constraint})
		if !errors.Is(err, test.want) || errors.Is(err, test.not) {
			t.Errorf("%s: error = %v, want %v and not %v", test.name, err, test.want, test.not)
		}
	}
}

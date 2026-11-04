package postgres

import (
	"errors"
	"testing"
)

func TestGrantIdentityRuntimeRefusesUnsafeNames(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct{ role, database string }{
		"quoted role":       {role: `identity"; DROP`, database: "meshtransit_identity"},
		"upper case role":   {role: "Identity", database: "meshtransit_identity"},
		"empty role":        {role: "", database: "meshtransit_identity"},
		"spaced database":   {role: "identity_runtime", database: "meshtransit identity"},
		"too long database": {role: "identity_runtime", database: string(make([]byte, 64))},
	} {
		err := GrantIdentityRuntime(t.Context(), MigrationOptions{Database: test.database}, test.role)
		if !errors.Is(err, ErrInvalidMigrationOptions) {
			t.Errorf("%s: GrantIdentityRuntime() error = %v", name, err)
		}
	}
}

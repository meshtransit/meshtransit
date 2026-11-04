package postgres

import (
	"errors"
	"strings"
	"testing"
)

func TestSetLoginRolePasswordsRefusesUnsafeInput(t *testing.T) {
	t.Parallel()
	valid := "SCRAM-SHA-256$4096:W22ZaJ0SNY7soEsUEjb6gQ==$" + strings.Repeat("A", 43) + "=:" + strings.Repeat("B", 43) + "="
	for name, roles := range map[string][]RoleVerifier{
		"none":            nil,
		"quoted verifier": {{Role: "mesh_runtime", Verifier: valid + "'; DROP ROLE x; --"}},
		"plain password":  {{Role: "mesh_runtime", Verifier: "hunter2"}},
		"quoted role":     {{Role: `mesh"runtime`, Verifier: valid}},
		"upper case role": {{Role: "Mesh", Verifier: valid}},
		"one bad of many": {{Role: "mesh_runtime", Verifier: valid}, {Role: "mesh_worker", Verifier: "md5abc"}},
	} {
		if err := SetLoginRolePasswords(t.Context(), MigrationOptions{}, roles); !errors.Is(err, ErrInvalidMigrationOptions) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

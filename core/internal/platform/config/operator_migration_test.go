package config

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLoadOperatorMigrationConfig(t *testing.T) {
	t.Parallel()

	got, err := LoadOperatorMigration(mapLookup(validOperatorValues(nil)))
	if err != nil {
		t.Fatalf("LoadOperatorMigration() error = %v", err)
	}
	if got.PostgreSQL.Address != "database.internal:5432" || got.PostgreSQL.Database != "meshtransit" ||
		got.PostgreSQL.User != "postgres" {
		t.Fatalf("operator PostgreSQL = %+v", got.PostgreSQL)
	}
	if got.ConnectTimeout != 5*time.Second || got.LockTimeout != 5*time.Second || got.StatementTimeout != 30*time.Second {
		t.Fatalf("operator timeouts = (%s, %s, %s)", got.ConnectTimeout, got.LockTimeout, got.StatementTimeout)
	}
	if formatted := fmt.Sprintf("%#v", got); strings.Contains(formatted, "/run/secrets/operator") {
		t.Fatalf("formatted operator config exposed a file path: %s", formatted)
	}
}

// The operator command never borrows the migrator's or the runtime's
// settings, and rejects unsafe values without echoing them.
func TestLoadOperatorMigrationConfigRejectsMissingOrUnsafeValues(t *testing.T) {
	t.Parallel()

	values := validMigrationValues(nil)
	values[envPostgreSQLRuntimeUser] = "mesh_runtime"
	if _, err := LoadOperatorMigration(mapLookup(values)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("migrator settings stood in for the operator's: %v", err)
	}
	for key, value := range map[string]string{
		envOperatorPostgreSQLAddress:      ":5432",
		envOperatorPostgreSQLUser:         "mesh operator",
		envOperatorPostgreSQLPasswordFile: "secrets/postgres",
		envOperatorPostgreSQLCAFile:       "",
		envOperatorConnectTimeout:         "31s",
		envOperatorStatementTimeout:       "11m",
		envOperatorLockTimeout:            "30s",
	} {
		_, err := LoadOperatorMigration(mapLookup(validOperatorValues(map[string]string{key: value})))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("%s=%q: %v", key, value, err)
		}
		if value != "" && strings.Contains(err.Error(), value) {
			t.Fatalf("%s: error exposed %q: %v", key, value, err)
		}
	}
	if _, err := LoadOperatorMigration(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("LoadOperatorMigration(nil) error = %v", err)
	}
}

func validOperatorValues(overrides map[string]string) map[string]string {
	values := map[string]string{ //nolint:gosec // G101: fixtures contain file paths, not credentials.
		envOperatorPostgreSQLAddress:      "database.internal:5432",
		envOperatorPostgreSQLDatabase:     "meshtransit",
		envOperatorPostgreSQLUser:         "postgres",
		envOperatorPostgreSQLPasswordFile: "/run/secrets/operator-postgres-password",
		envOperatorPostgreSQLCAFile:       "/run/secrets/operator-postgres-ca.pem",
	}
	for key, value := range overrides {
		values[key] = value
	}
	return values
}

func TestLoadOperatorLoginPasswordFiles(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		value string
		want  []string
		valid bool
	}{
		"absent":    {value: "", valid: true},
		"one":       {value: "mesh_control=/run/a/password", want: []string{"mesh_control"}, valid: true},
		"two":       {value: "mesh_control=/run/a, mesh_api=/run/b", want: []string{"mesh_api", "mesh_control"}, valid: true},
		"duplicate": {value: "mesh_control=/run/a,mesh_control=/run/b"},
		"no file":   {value: "mesh_control"},
		"relative":  {value: "mesh_control=run/a"},
		"bad name":  {value: "Mesh-Control=/run/a"},
	} {
		files, err := loadOperatorLoginPasswordFiles(func(key string) (string, bool) {
			return test.value, key == envOperatorLoginPasswordFiles && test.value != ""
		})
		if (err == nil) != test.valid {
			t.Errorf("%s: error = %v, want valid %v", name, err, test.valid)
			continue
		}
		var names []string
		for login := range files {
			names = append(names, login)
		}
		slices.Sort(names)
		if test.valid && !slices.Equal(names, test.want) {
			t.Errorf("%s: logins = %v, want %v", name, names, test.want)
		}
	}
}

func TestLoadOperatorConnectionLimits(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		value string
		want  map[string]int
		valid bool
	}{
		"absent": {value: "", want: map[string]int{}, valid: true},
		"three": {value: "mesh_runtime=13, mesh_control=13,mesh_worker=4",
			want: map[string]int{"mesh_runtime": 13, "mesh_control": 13, "mesh_worker": 4}, valid: true},
		"self-host":    {value: "mesh_all=20", want: map[string]int{"mesh_all": 20}, valid: true},
		"duplicate":    {value: "mesh_runtime=1,mesh_runtime=2"},
		"not serving":  {value: "postgres=10"},
		"migrator":     {value: "mesh_migrator=10"},
		"zero":         {value: "mesh_runtime=0"},
		"unlimited":    {value: "mesh_runtime=-1", want: map[string]int{"mesh_runtime": -1}, valid: true},
		"below -1":     {value: "mesh_runtime=-2"},
		"too many":     {value: "mesh_runtime=10001"},
		"not a number": {value: "mesh_runtime=ten"},
		"no limit":     {value: "mesh_runtime"},
	} {
		limits, err := loadOperatorConnectionLimits(func(key string) (string, bool) {
			return test.value, key == envOperatorConnectionLimits && test.value != ""
		})
		if (err == nil) != test.valid {
			t.Errorf("%s: error = %v, want valid %v", name, err, test.valid)
			continue
		}
		if test.valid && !maps.Equal(limits, test.want) {
			t.Errorf("%s: limits = %v, want %v", name, limits, test.want)
		}
		if err != nil && strings.Contains(err.Error(), test.value) {
			t.Errorf("%s: error echoes the value: %v", name, err)
		}
	}
}

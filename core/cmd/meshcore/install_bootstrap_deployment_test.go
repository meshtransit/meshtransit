package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/config"
)

func TestInstallBootstrapDeployment(t *testing.T) {
	t.Parallel()
	migration := map[string]string{
		"MESHTRANSIT_MIGRATION_POSTGRES_ADDRESS": "db.example.test:5432", "MESHTRANSIT_MIGRATION_POSTGRES_DATABASE": "meshtransit",
		"MESHTRANSIT_MIGRATION_POSTGRES_USER":          "mesh_migrator",
		"MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE": "/run/meshtransit/secrets/postgres-password",
		"MESHTRANSIT_MIGRATION_POSTGRES_CA_FILE":       "/run/meshtransit/ca/postgres.crt",
		"MESHTRANSIT_MIGRATION_ACTOR":                  "chart:mt",
	}
	for _, test := range []struct {
		name       string
		values     map[string]string
		installed  bool
		checkErr   error
		wantCode   int
		wantApply  bool
		wantOutput string
	}{
		{name: "installed: nothing", values: migration, installed: true, wantOutput: "already installed"},
		{name: "new: applies", values: migration, wantApply: true},
		{name: "unreachable database", values: migration, checkErr: errors.New("dial"), wantCode: 1,
			wantOutput: "bootstrap_unavailable"},
		{name: "no migration settings", values: map[string]string{}, wantCode: 1, wantOutput: "invalid_migration_configuration"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			applied := false
			dependencies := productionInstallDependencies()
			dependencies.deploymentInstalled = func(context.Context, postgresadapter.MigrationOptions) (bool, error) {
				return test.installed, test.checkErr
			}
			dependencies.bootstrapDeployment = func(context.Context, config.LookupFunc, io.Writer, io.Writer) int {
				applied = true
				return 0
			}
			var output, errorOutput bytes.Buffer
			code := runInstall(context.Background(), []string{"bootstrap", "deployment"}, mapLookupFunc(test.values),
				&output, &errorOutput, dependencies)
			if code != test.wantCode || applied != test.wantApply ||
				!strings.Contains(output.String()+errorOutput.String(), test.wantOutput) {
				t.Fatalf("%d applied=%v %s %s", code, applied, output.String(), errorOutput.String())
			}
		})
	}
}

func mapLookupFunc(values map[string]string) config.LookupFunc {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

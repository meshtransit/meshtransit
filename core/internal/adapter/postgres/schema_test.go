package postgres

import (
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/core/migrations"
)

func TestValidateRuntimeSchemaCompatibility(t *testing.T) {
	t.Parallel()

	catalog := migrations.Catalog()
	valid := runtimeSchemaCompatibility{
		currentVersion:          migrations.LatestVersion(),
		minimumReaderGeneration: 1,
		maximumReaderGeneration: 1,
		minimumWriterGeneration: 1,
		maximumWriterGeneration: 1,
		migrationState:          "clean",
		currentChecksum:         catalog[len(catalog)-1].Checksum,
		migrationResult:         "succeeded",
		knownHistoryValid:       true,
		currentUser:             "mesh_runtime",
		runtimeRoleSafe:         true,
	}
	tests := []struct {
		name          string
		compatibility runtimeSchemaCompatibility
		wantErr       bool
	}{
		{name: "current", compatibility: valid},
		{name: "dirty", compatibility: withRuntimeMigrationState(valid, "dirty"), wantErr: true},
		{name: "reader incompatible", compatibility: withRuntimeReaderRange(valid, 2, 3), wantErr: true},
		{name: "writer incompatible", compatibility: withRuntimeWriterRange(valid, 2, 3), wantErr: true},
		{name: "checksum drift", compatibility: withRuntimeChecksum(valid, "changed"), wantErr: true},
		{name: "failed migration", compatibility: withRuntimeMigrationResult(valid, "failed"), wantErr: true},
		{name: "known history drift", compatibility: withRuntimeHistoryValidity(valid, false), wantErr: true},
		{name: "unexpected runtime user", compatibility: withRuntimeUser(valid, "mesh_migrator"), wantErr: true},
		{name: "unsafe runtime role", compatibility: withRuntimeRoleSafety(valid, false), wantErr: true},
		{
			name:          "compatible future schema",
			compatibility: withRuntimeVersion(valid, migrations.LatestVersion()+1, "future-checksum"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := validateRuntimeSchemaCompatibility(
				catalog,
				migrations.ApplicationGeneration,
				"mesh_runtime",
				test.compatibility,
			)
			if test.wantErr {
				if !errors.Is(err, ErrSchemaIncompatible) {
					t.Fatalf("validateRuntimeSchemaCompatibility() error = %v, want ErrSchemaIncompatible", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateRuntimeSchemaCompatibility() error = %v", err)
			}
		})
	}
}

func withRuntimeMigrationState(
	value runtimeSchemaCompatibility,
	state string,
) runtimeSchemaCompatibility {
	value.migrationState = state
	return value
}

func withRuntimeReaderRange(
	value runtimeSchemaCompatibility,
	minimum, maximum int64,
) runtimeSchemaCompatibility {
	value.minimumReaderGeneration = minimum
	value.maximumReaderGeneration = maximum
	return value
}

func withRuntimeWriterRange(
	value runtimeSchemaCompatibility,
	minimum, maximum int64,
) runtimeSchemaCompatibility {
	value.minimumWriterGeneration = minimum
	value.maximumWriterGeneration = maximum
	return value
}

func withRuntimeChecksum(
	value runtimeSchemaCompatibility,
	checksum string,
) runtimeSchemaCompatibility {
	value.currentChecksum = checksum
	return value
}

func withRuntimeMigrationResult(
	value runtimeSchemaCompatibility,
	result string,
) runtimeSchemaCompatibility {
	value.migrationResult = result
	return value
}

func withRuntimeVersion(
	value runtimeSchemaCompatibility,
	version int64,
	checksum string,
) runtimeSchemaCompatibility {
	value.currentVersion = version
	value.currentChecksum = checksum
	return value
}

func withRuntimeHistoryValidity(
	value runtimeSchemaCompatibility,
	valid bool,
) runtimeSchemaCompatibility {
	value.knownHistoryValid = valid
	return value
}

func withRuntimeUser(
	value runtimeSchemaCompatibility,
	user string,
) runtimeSchemaCompatibility {
	value.currentUser = user
	return value
}

func withRuntimeRoleSafety(
	value runtimeSchemaCompatibility,
	safe bool,
) runtimeSchemaCompatibility {
	value.runtimeRoleSafe = safe
	return value
}

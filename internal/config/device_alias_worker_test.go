package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestDeviceAliasWorkerConfigurationIsExplicitAndBounded(t *testing.T) {
	t.Parallel()
	defaults, err := Load(mapLookup(validProcessValues(nil)))
	if err != nil || defaults.DeviceAliasWorker != nil {
		t.Fatal("worker enabled by default", err)
	}
	for _, role := range []string{"all", "worker"} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			got, err := Load(mapLookup(validProcessValues(map[string]string{
				envRole: role, envDeviceAliasWorkerEnabled: "true",
				envDeviceAliasWorkerDeployment: "01890f00-0000-7000-8000-000000000001",
			})))
			if err != nil || got.DeviceAliasWorker == nil {
				t.Fatal("explicit worker rejected", err)
			}
			worker := got.DeviceAliasWorker
			if worker.BatchSize != 8 || worker.PollInterval != 500*time.Millisecond || worker.OperationTimeout != 10*time.Second {
				t.Fatal("unsafe defaults")
			}
			if strings.Contains(fmt.Sprintf("%v %#v %s", worker, worker, worker.LogValue()), worker.DeploymentID.String()) {
				t.Fatal("assignment exposed by formatting")
			}
		})
	}
}

func TestDeviceAliasWorkerRejectsInvalidAssignmentAndBounds(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, key, value string }{
		{"missing deployment", envDeviceAliasWorkerDeployment, ""},
		{"non-v7 deployment", envDeviceAliasWorkerDeployment, "01890f00-0000-4000-8000-000000000001"},
		{"api role", envRole, "api"}, {"control role", envRole, "control"},
		{"ambiguous flag", envDeviceAliasWorkerEnabled, "TRUE"},
		{"zero batch", envDeviceAliasWorkerBatch, "0"}, {"excess batch", envDeviceAliasWorkerBatch, "129"},
		{"short poll", envDeviceAliasWorkerPoll, "99ms"}, {"long poll", envDeviceAliasWorkerPoll, "61s"},
		{"short timeout", envDeviceAliasWorkerTimeout, "99ms"}, {"long timeout", envDeviceAliasWorkerTimeout, "16s"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := validProcessValues(map[string]string{envRole: "worker", envDeviceAliasWorkerEnabled: "true", envDeviceAliasWorkerDeployment: "01890f00-0000-7000-8000-000000000001", test.key: test.value})
			_, err := Load(mapLookup(values))
			if !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe setting accepted", err)
			}
			if test.key != envRole && !strings.Contains(err.Error(), test.key) {
				t.Fatal("missing setting name", err)
			}
		})
	}
	for _, key := range []string{envDeviceAliasWorkerDeployment, envDeviceAliasWorkerBatch, envDeviceAliasWorkerPoll, envDeviceAliasWorkerTimeout} {
		t.Run("disabled "+key, func(t *testing.T) {
			t.Parallel()
			_, err := Load(mapLookup(validProcessValues(map[string]string{key: "unexpected"})))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), key) {
				t.Fatal("disabled setting accepted", err)
			}
		})
	}
}

func TestControlMapDeviceAliasesRequireStrictOptIn(t *testing.T) {
	t.Parallel()
	for _, flag := range []string{"true", "false", "TRUE", "1", "unexpected"} {
		t.Run(flag, func(t *testing.T) {
			t.Parallel()
			got, err := Load(mapLookup(validProcessValues(map[string]string{envRole: "control", envControlMapDeviceAliases: flag})))
			if flag != "true" && flag != "false" {
				if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), envControlMapDeviceAliases) {
					t.Fatal("ambiguous map flag accepted", err)
				}
				return
			}
			if err != nil || got.Control.Map.EnableDeviceAliases != (flag == "true") {
				t.Fatal("map opt-in lost", err)
			}
		})
	}
}

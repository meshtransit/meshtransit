package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestContractExpiryWorkerConfigurationIsExplicitAndBounded(t *testing.T) {
	t.Parallel()
	defaults, err := Load(mapLookup(validProcessValues(nil)))
	if err != nil || defaults.ContractExpiryWorker != nil {
		t.Fatal("expiry worker enabled by default", err)
	}
	for _, role := range []string{"all", "worker"} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			got, err := Load(mapLookup(validProcessValues(map[string]string{
				envRole: role, envContractExpiryWorkerEnabled: "true",
				envContractExpiryWorkerDeployment: "01890f00-0000-7000-8000-000000000001",
			})))
			if err != nil || got.ContractExpiryWorker == nil {
				t.Fatal("explicit expiry worker rejected", err)
			}
			worker := got.ContractExpiryWorker
			if worker.BatchSize != 16 || worker.PollInterval != 2*time.Second || worker.OperationTimeout != 10*time.Second {
				t.Fatalf("unexpected defaults %+v", *worker)
			}
			if strings.Contains(fmt.Sprintf("%v %#v %s", worker, worker, worker.LogValue()), worker.DeploymentID.String()) {
				t.Fatal("assignment exposed by formatting")
			}
		})
	}
}

func TestContractExpiryWorkerRejectsInvalidAssignmentAndBounds(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, key, value string }{
		{"missing deployment", envContractExpiryWorkerDeployment, ""},
		{"non-v7 deployment", envContractExpiryWorkerDeployment, "01890f00-0000-4000-8000-000000000001"},
		{"api role", envRole, "api"}, {"control role", envRole, "control"},
		{"ambiguous flag", envContractExpiryWorkerEnabled, "TRUE"},
		{"zero batch", envContractExpiryWorkerBatch, "0"}, {"excess batch", envContractExpiryWorkerBatch, "129"},
		{"short poll", envContractExpiryWorkerPoll, "99ms"}, {"long poll", envContractExpiryWorkerPoll, "61s"},
		{"short timeout", envContractExpiryWorkerTimeout, "99ms"}, {"long timeout", envContractExpiryWorkerTimeout, "16s"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := validProcessValues(map[string]string{
				envRole: "worker", envContractExpiryWorkerEnabled: "true",
				envContractExpiryWorkerDeployment: "01890f00-0000-7000-8000-000000000001", test.key: test.value,
			})
			_, err := Load(mapLookup(values))
			if !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe setting accepted", err)
			}
			if test.key != envRole && !strings.Contains(err.Error(), test.key) {
				t.Fatal("missing setting name", err)
			}
		})
	}
	for _, key := range []string{envContractExpiryWorkerDeployment, envContractExpiryWorkerBatch, envContractExpiryWorkerPoll, envContractExpiryWorkerTimeout} {
		t.Run("disabled "+key, func(t *testing.T) {
			t.Parallel()
			_, err := Load(mapLookup(validProcessValues(map[string]string{key: "unexpected"})))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), key) {
				t.Fatal("disabled setting accepted", err)
			}
		})
	}
}

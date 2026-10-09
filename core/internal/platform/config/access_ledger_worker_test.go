package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestAccessLedgerWorkerConfigurationIsExplicitAndBounded(t *testing.T) {
	t.Parallel()
	defaults, err := Load(mapLookup(validProcessValues(nil)))
	if err != nil || defaults.AccessLedgerWorker != nil {
		t.Fatal("access ledger worker enabled by default", err)
	}
	got, err := Load(mapLookup(validProcessValues(map[string]string{
		envRole: "worker", envAccessLedgerWorkerEnabled: "true",
		envAccessLedgerWorkerDeployment: "01890f00-0000-7000-8000-000000000001",
	})))
	if err != nil || got.AccessLedgerWorker == nil {
		t.Fatal("explicit access ledger worker rejected", err)
	}
	worker := got.AccessLedgerWorker
	if worker.BatchSize != 16 || worker.PollInterval != 3*time.Second || worker.PruneInterval != time.Hour ||
		worker.OperationTimeout != 25*time.Second {
		t.Fatalf("unexpected defaults %+v", *worker)
	}
	if strings.Contains(fmt.Sprintf("%v %#v %s", worker, worker, worker.LogValue()), worker.DeploymentID.String()) {
		t.Fatal("assignment exposed by formatting")
	}
}

func TestAccessLedgerWorkerRejectsInvalidAssignmentAndBounds(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, key, value string }{
		{"missing deployment", envAccessLedgerWorkerDeployment, ""},
		{"api role", envRole, "api"},
		{"ambiguous flag", envAccessLedgerWorkerEnabled, "yes"},
		{"excess batch", envAccessLedgerWorkerBatch, "65"},
		{"short poll", envAccessLedgerWorkerPoll, "99ms"},
		{"short prune", envAccessLedgerWorkerPrune, "59s"},
		{"long timeout", envAccessLedgerWorkerTimeout, "31s"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := validProcessValues(map[string]string{
				envRole: "worker", envAccessLedgerWorkerEnabled: "true",
				envAccessLedgerWorkerDeployment: "01890f00-0000-7000-8000-000000000001", test.key: test.value,
			})
			if _, err := Load(mapLookup(values)); !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe setting accepted", err)
			}
		})
	}
	values := validProcessValues(map[string]string{envAccessLedgerWorkerBatch: "4"})
	if _, err := Load(mapLookup(values)); !errors.Is(err, ErrInvalid) {
		t.Fatal("setting without the enabled flag accepted", err)
	}
}

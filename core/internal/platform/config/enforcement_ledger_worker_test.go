package config

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestEnforcementLedgerWorkerConfigurationIsExplicitAndBounded(t *testing.T) {
	t.Parallel()
	defaults, err := Load(mapLookup(validProcessValues(nil)))
	if err != nil || defaults.EnforcementLedgerWorker != nil {
		t.Fatal("enforcement ledger worker enabled by default", err)
	}
	got, err := Load(mapLookup(validProcessValues(map[string]string{
		envRole: "worker", envEnforcementLedgerWorkerEnabled: "true",
		envEnforcementLedgerWorkerDeployment: "01890f00-0000-7000-8000-000000000001",
	})))
	if err != nil || got.EnforcementLedgerWorker == nil {
		t.Fatal("explicit enforcement ledger worker rejected", err)
	}
	worker := got.EnforcementLedgerWorker
	if worker.PollInterval != 15*time.Second || worker.PruneInterval != time.Hour ||
		worker.OperationTimeout != 10*time.Second {
		t.Fatalf("unexpected defaults %+v", *worker)
	}
	if strings.Contains(fmt.Sprintf("%v %#v %s", worker, worker, worker.LogValue()), worker.DeploymentID.String()) {
		t.Fatal("assignment exposed by formatting")
	}
}

func TestEnforcementLedgerWorkerRejectsInvalidAssignmentAndBounds(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, key, value string }{
		{"missing deployment", envEnforcementLedgerWorkerDeployment, ""},
		{"api role", envRole, "api"},
		{"ambiguous flag", envEnforcementLedgerWorkerEnabled, "yes"},
		{"long poll", envEnforcementLedgerWorkerPoll, "6m"},
		{"short poll", envEnforcementLedgerWorkerPoll, "99ms"},
		{"short prune", envEnforcementLedgerWorkerPrune, "59s"},
		{"long timeout", envEnforcementLedgerWorkerTimeout, "31s"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := validProcessValues(map[string]string{
				envRole: "worker", envEnforcementLedgerWorkerEnabled: "true",
				envEnforcementLedgerWorkerDeployment: "01890f00-0000-7000-8000-000000000001", test.key: test.value,
			})
			if _, err := Load(mapLookup(values)); !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe setting accepted", err)
			}
		})
	}
	values := validProcessValues(map[string]string{envEnforcementLedgerWorkerPoll: "20s"})
	if _, err := Load(mapLookup(values)); !errors.Is(err, ErrInvalid) {
		t.Fatal("setting without the enabled flag accepted", err)
	}
}

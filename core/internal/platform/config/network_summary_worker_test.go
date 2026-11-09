package config

import (
	"testing"
	"time"

	"meshtransit.net/core/internal/platform/app"
)

func networkSummaryLookup(values map[string]string) LookupFunc {
	return func(name string) (string, bool) {
		value, present := values[name]
		return value, present
	}
}

func TestNetworkSummaryWorkerIsOffByDefault(t *testing.T) {
	t.Parallel()
	settings, err := loadNetworkSummaryWorkerConfig(networkSummaryLookup(nil), app.RoleWorker)
	if err != nil || settings != nil {
		t.Fatalf("default = %v, %v", settings, err)
	}
	if _, err := loadNetworkSummaryWorkerConfig(networkSummaryLookup(map[string]string{
		envNetworkSummaryWorkerBatch: "8"}), app.RoleWorker); err == nil {
		t.Fatal("a setting for a worker that is off was accepted")
	}
}

func TestNetworkSummaryWorkerDefaultsAndBounds(t *testing.T) {
	t.Parallel()
	base := map[string]string{envNetworkSummaryWorkerEnabled: "true",
		envNetworkSummaryWorkerDeployment: "01890f00-0000-7000-8000-000000000001"}
	settings, err := loadNetworkSummaryWorkerConfig(networkSummaryLookup(base), app.RoleWorker)
	if err != nil || settings.BatchSize != 8 || settings.PollInterval != 5*time.Second ||
		settings.OperationTimeout != 10*time.Second || settings.Lease != 2*time.Minute {
		t.Fatalf("defaults = %+v, %v", settings, err)
	}
	if _, err := loadNetworkSummaryWorkerConfig(networkSummaryLookup(base), app.RoleAPI); err == nil {
		t.Fatal("the API role accepted the worker")
	}
	for name, value := range map[string]string{
		envNetworkSummaryWorkerBatch: "65", envNetworkSummaryWorkerPoll: "100ms",
		envNetworkSummaryWorkerLease: "80s", envNetworkSummaryWorkerDeployment: "not-a-uuid",
	} {
		values := map[string]string{}
		for key, existing := range base {
			values[key] = existing
		}
		values[name] = value
		if _, err := loadNetworkSummaryWorkerConfig(networkSummaryLookup(values), app.RoleWorker); err == nil {
			t.Errorf("%s=%s accepted", name, value)
		}
	}
}

package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoadPrivateEndpointWorkerIsOptInAndRedacted(t *testing.T) {
	t.Parallel()

	defaults, err := Load(mapLookup(validProcessValues(nil)))
	if err != nil {
		t.Fatalf("Load(defaults) error = %v", err)
	}
	if defaults.PrivateEndpointWorker != nil {
		t.Fatalf("PrivateEndpointWorker = %v, want disabled by default", defaults.PrivateEndpointWorker)
	}

	values := validProcessValues(map[string]string{
		envRole:                             "worker",
		envPrivateEndpointWorkerEnabled:     "true",
		envPrivateEndpointDeploymentID:      "01890f00-0000-7000-8000-000000000001",
		envPrivateEndpointReconcilerID:      "gateway-sgp-1",
		envPrivateEndpointBatchSize:         "12",
		envPrivateEndpointPollInterval:      "2s",
		envPrivateEndpointOperationTimeout:  "7s",
		envPrivateEndpointInitialRetryDelay: "3s",
		envPrivateEndpointMaximumRetryDelay: "2m",
		envPrivateEndpointAgentOrigin:       "https://route-agent.meshtransit.internal:8443",
		envPrivateEndpointAgentCAFile:       "/run/secrets/route-agent-ca.pem",
		envPrivateEndpointAgentCertificate:  "/run/secrets/route-agent-client.pem",
		envPrivateEndpointAgentPrivateKey:   "/run/secrets/route-agent-client-key.pem",
	})
	configured, err := Load(mapLookup(values))
	if err != nil {
		t.Fatalf("Load(configured) error = %v", err)
	}
	worker := configured.PrivateEndpointWorker
	if worker == nil || worker.ReconcilerID != "gateway-sgp-1" || worker.BatchSize != 12 ||
		worker.PollInterval != 2*time.Second || worker.OperationTimeout != 7*time.Second ||
		worker.InitialRetryDelay != 3*time.Second || worker.MaximumRetryDelay != 2*time.Minute {
		t.Fatalf("PrivateEndpointWorker = %+v, want bounded explicit settings", worker)
	}
	if worker.String() != redactedValue || strings.Contains(worker.GoString(), worker.ReconcilerID) {
		t.Fatal("Private Endpoint worker configuration formatting exposed assignment")
	}
}

func TestLoadPrivateEndpointWorkerRejectsPartialOrUnsafeConfiguration(t *testing.T) {
	t.Parallel()

	base := map[string]string{
		envRole:                            "worker",
		envPrivateEndpointWorkerEnabled:    "true",
		envPrivateEndpointDeploymentID:     "01890f00-0000-7000-8000-000000000001",
		envPrivateEndpointReconcilerID:     "gateway-sgp-1",
		envPrivateEndpointAgentOrigin:      "https://route-agent.meshtransit.internal:8443",
		envPrivateEndpointAgentCAFile:      "/run/secrets/route-agent-ca.pem",
		envPrivateEndpointAgentCertificate: "/run/secrets/route-agent-client.pem",
		envPrivateEndpointAgentPrivateKey:  "/run/secrets/route-agent-client-key.pem",
	}
	tests := []struct{ name, key, value string }{
		{name: "cleartext agent", key: envPrivateEndpointAgentOrigin, value: "http://route-agent:8080"},
		{name: "agent path", key: envPrivateEndpointAgentOrigin, value: "https://route-agent/routes"},
		{name: "empty agent port", key: envPrivateEndpointAgentOrigin, value: "https://route-agent:"},
		{name: "zero agent port", key: envPrivateEndpointAgentOrigin, value: "https://route-agent:0"},
		{name: "invalid reconciler", key: envPrivateEndpointReconcilerID, value: "gateway sgp"},
		{name: "short timeout", key: envPrivateEndpointOperationTimeout, value: "99ms"},
		{name: "retry inversion", key: envPrivateEndpointMaximumRetryDelay, value: "500ms"},
		{name: "relative key", key: envPrivateEndpointAgentPrivateKey, value: "client-key.pem"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			settings := make(map[string]string, len(base)+1)
			for key, value := range base {
				settings[key] = value
			}
			settings[test.key] = test.value
			_, err := Load(mapLookup(validProcessValues(settings)))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.key) {
				t.Fatalf("Load() error = %v, want invalid %s", err, test.key)
			}
		})
	}
}

func TestLoadPrivateEndpointWorkerRejectsSettingsWhileDisabled(t *testing.T) {
	t.Parallel()
	_, err := Load(mapLookup(validProcessValues(map[string]string{
		envPrivateEndpointReconcilerID: "unexpected",
	})))
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), envPrivateEndpointReconcilerID) {
		t.Fatalf("Load() error = %v, want disabled-setting rejection", err)
	}
}

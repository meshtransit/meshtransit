//go:build integration

package ts2021

import (
	"os"
	"testing"
)

const (
	integrationControlURLEnv         = "MESHTRANSIT_INTEGRATION_CONTROL_URL"
	integrationControlFingerprintEnv = "MESHTRANSIT_INTEGRATION_CONTROL_FINGERPRINT"
)

func TestClient_ProbeLiveControl(t *testing.T) {
	t.Parallel()

	controlURL, expectedFingerprint := integrationControlConfig(t)

	result, err := New().Probe(t.Context(), controlURL)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if result.Protocol != "ts2021" || result.Capability != 142 ||
		!result.NoiseEstablished || result.NoiseVersion != 142 {
		t.Fatalf("Probe() result = %#v, want capability-142 Noise session", result)
	}
	if !constantTimeFingerprintEqual(result.KeyFingerprint, expectedFingerprint) {
		t.Fatalf("Probe() fingerprint does not match configured control identity")
	}
}

func integrationControlConfig(t *testing.T) (string, string) {
	t.Helper()

	controlURL := os.Getenv(integrationControlURLEnv)
	expectedFingerprint := os.Getenv(integrationControlFingerprintEnv)
	if controlURL == "" || expectedFingerprint == "" {
		t.Skip("live control endpoint and fingerprint are not configured")
	}

	return controlURL, expectedFingerprint
}

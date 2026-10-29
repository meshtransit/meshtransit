package config

import (
	"testing"

	"meshtransit.net/core/internal/domain/kubecluster"
)

func TestLoadKubernetesGatewayToken(t *testing.T) {
	t.Parallel()
	for value, want := range map[string]kubecluster.GatewayTokenMode{
		"":         kubecluster.GatewayTokenRatchet,
		"observe":  kubecluster.GatewayTokenObserve,
		"ratchet":  kubecluster.GatewayTokenRatchet,
		"required": kubecluster.GatewayTokenRequired,
	} {
		lookup := func(name string) (string, bool) {
			if name == envKubernetesGatewayToken && value != "" {
				return value, true
			}
			return "", false
		}
		if got, err := loadKubernetesGatewayToken(lookup); err != nil || got != want {
			t.Errorf("%q: %q, %v", value, got, err)
		}
	}
	for _, value := range []string{"off", "Ratchet", "enforce", " required"} {
		lookup := func(name string) (string, bool) { return value, name == envKubernetesGatewayToken }
		if _, err := loadKubernetesGatewayToken(lookup); err == nil {
			t.Errorf("%q accepted", value)
		}
	}
}

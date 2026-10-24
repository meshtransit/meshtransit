package config

import (
	"fmt"
	"slices"
	"testing"
)

func TestLoadDNSZones(t *testing.T) {
	t.Parallel()
	lookup := func(values map[string]string) LookupFunc {
		return func(key string) (string, bool) {
			value, ok := values[key]
			return value, ok
		}
	}
	zones, err := loadDNSZones(lookup(nil))
	if err != nil || zones.Enabled || len(zones.ProtectedNames) != 0 {
		t.Fatalf("defaults = %+v, %v", zones, err)
	}
	zones, err = loadDNSZones(lookup(map[string]string{envDNSZonesEnabled: "true",
		envDNSProtectedNames: " Control.Example.NET., api.example.net,control.example.net"}))
	if err != nil || !zones.Enabled || !slices.Equal(zones.ProtectedNames, []string{"control.example.net", "api.example.net"}) {
		t.Fatalf("configured = %+v, %v", zones, err)
	}
	for name, values := range map[string]map[string]string{
		"enabled not a boolean": {envDNSZonesEnabled: "yes"},
		"empty name":            {envDNSProtectedNames: "a.example,,b.example"},
		"not a host name":       {envDNSProtectedNames: "https://control.example.net"},
		"leading dot":           {envDNSProtectedNames: ".example.net"},
	} {
		if _, err := loadDNSZones(lookup(values)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDNSProtectedNamesAddsTheDeploymentsOwnHosts(t *testing.T) {
	t.Parallel()
	config := Config{
		DNSZones:            DNSZonesConfig{ProtectedNames: []string{"control.example.net"}},
		Identity:            &IdentityConfig{Issuer: "https://id.example.net/dex"},
		BrowserRegistration: &BrowserRegistrationConfig{Origin: "https://control.example.net"},
		Interchange:         &InterchangeConfig{CoreURL: "https://core.example.net:8443"},
	}
	if names := config.DNSProtectedNames(); !slices.Equal(names,
		[]string{"id.example.net", "control.example.net", "core.example.net"}) {
		t.Fatalf("DNSProtectedNames() = %v", names)
	}
}

// The deployment's own hosts come first, so 64 configured names never push
// them past a map's bound (TD-CLI-70).
func TestDNSProtectedNamesPutTheDeploymentsHostsFirst(t *testing.T) {
	t.Parallel()
	configured := make([]string, 0, 64)
	for index := range 64 {
		configured = append(configured, fmt.Sprintf("name%d.example.net", index))
	}
	config := Config{
		DNSZones: DNSZonesConfig{ProtectedNames: configured},
		Identity: &IdentityConfig{Issuer: "https://id.example.net/dex"},
	}
	if names := config.DNSProtectedNames(); len(names) != 65 || names[0] != "id.example.net" {
		t.Fatalf("DNSProtectedNames() = %d names, first %q", len(names), names[0])
	}
}

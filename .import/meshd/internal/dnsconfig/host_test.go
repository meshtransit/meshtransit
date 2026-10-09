package dnsconfig

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/meshtransit/meshd/internal/netadmin"
)

func TestResolvedHostAppliesRoutingDomainsAndResets(t *testing.T) {
	t.Parallel()

	admin := &fakeDNSAdministrator{}
	endpoint := staticEndpoint{value: testDNSEndpoint(), ready: true}
	host, err := NewResolvedHost(admin, endpoint)
	if err != nil {
		t.Fatalf("NewResolvedHost() error = %v", err)
	}
	plan, err := Compile(dnsSnapshot())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	plan.DefaultResolvers = []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")}
	if err := host.Apply(t.Context(), plan); err != nil {
		t.Fatalf("enabled Apply() error = %v", err)
	}
	if len(admin.configs) != 1 {
		t.Fatalf("configure calls = %d, want 1", len(admin.configs))
	}
	config := admin.configs[0]
	if config.Endpoint != endpoint.value || !config.DefaultRoute ||
		!slices.Equal(config.SearchDomains, []string{"example.mesh"}) ||
		!slices.Contains(config.RouteDomains, ".") ||
		slices.Contains(config.RouteDomains, "example.mesh") {
		t.Fatalf("resolved config = %#v", config)
	}
	if err := host.Apply(t.Context(), Plan{}); err != nil {
		t.Fatalf("disabled Apply() error = %v", err)
	}
	if admin.resetCalls != 1 {
		t.Fatalf("reset calls = %d, want 1", admin.resetCalls)
	}
}

func TestResolvedHostRestoresPreviousConfigAfterFailure(t *testing.T) {
	t.Parallel()

	admin := &fakeDNSAdministrator{}
	host, err := NewResolvedHost(admin, staticEndpoint{value: testDNSEndpoint(), ready: true})
	if err != nil {
		t.Fatalf("NewResolvedHost() error = %v", err)
	}
	plan, err := Compile(dnsSnapshot())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if err := host.Apply(t.Context(), plan); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}
	admin.failAt = 2
	updated := clonePlan(plan)
	updated.Revision++
	updated.SearchDomains = append(updated.SearchDomains, "service.example.mesh")
	if err := host.Apply(t.Context(), updated); err == nil {
		t.Fatal("updated Apply() error = nil")
	}
	if len(admin.configs) != 3 ||
		!equalDNSConfig(admin.configs[0], admin.configs[2]) {
		t.Fatalf("rollback configs = %#v", admin.configs)
	}
}

func TestResolvedHostRejectsMissingEndpoint(t *testing.T) {
	t.Parallel()

	host, err := NewResolvedHost(&fakeDNSAdministrator{}, staticEndpoint{})
	if err != nil {
		t.Fatalf("NewResolvedHost() error = %v", err)
	}
	if err := host.Apply(t.Context(), Plan{Enabled: true}); err == nil {
		t.Fatal("Apply() error = nil")
	}
}

func testDNSEndpoint() netadmin.DNSEndpoint {
	return netadmin.DNSEndpoint{
		InterfaceName: "meshdns0",
		Resolver:      netip.MustParseAddrPort("192.0.2.53:1053"),
	}
}

type staticEndpoint struct {
	value netadmin.DNSEndpoint
	ready bool
}

func (s staticEndpoint) Endpoint() (netadmin.DNSEndpoint, bool) {
	return s.value, s.ready
}

type fakeDNSAdministrator struct {
	configs    []netadmin.DNSConfig
	failAt     int
	resetCalls int
}

func (f *fakeDNSAdministrator) ConfigureDNS(
	_ context.Context,
	config netadmin.DNSConfig,
) error {
	f.configs = append(f.configs, cloneDNSConfig(config))
	if f.failAt != 0 && len(f.configs) == f.failAt {
		return errors.New("configure failed")
	}

	return nil
}

func (f *fakeDNSAdministrator) ResetDNS(context.Context) error {
	f.resetCalls++

	return nil
}

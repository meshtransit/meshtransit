//go:build linux

package netadmin

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestResolvectlApplyAndReset(t *testing.T) {
	t.Parallel()

	runner := &fakeCommandRunner{}
	configurator := &resolvectlConfigurator{path: "/usr/bin/resolvectl", runner: runner}
	config := testDNSConfig()
	if err := configurator.Apply(t.Context(), config); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := configurator.Reset(t.Context(), config.Endpoint); err != nil {
		t.Fatalf("Reset() error = %v", err)
	}
	want := [][]string{
		{"dns", "meshdns0", "192.0.2.53:1053"},
		{"domain", "meshdns0", "mesh.example", "~.", "~64.100.in-addr.arpa"},
		{"default-route", "meshdns0", "true"},
		{"llmnr", "meshdns0", "no"},
		{"mdns", "meshdns0", "no"},
		{"dnssec", "meshdns0", "no"},
		{"revert", "meshdns0"},
	}
	if !equalCommandCalls(runner.calls, want) {
		t.Fatalf("command calls = %v, want %v", runner.calls, want)
	}
}

func TestResolvectlApplyRollsBackPartialFailure(t *testing.T) {
	t.Parallel()

	runner := &fakeCommandRunner{failAt: 2}
	configurator := &resolvectlConfigurator{path: "/usr/bin/resolvectl", runner: runner}
	err := configurator.Apply(t.Context(), testDNSConfig())
	if err == nil || !strings.Contains(err.Error(), "running resolvectl domain") {
		t.Fatalf("Apply() error = %v", err)
	}
	want := [][]string{
		{"dns", "meshdns0", "192.0.2.53:1053"},
		{"domain", "meshdns0", "mesh.example", "~.", "~64.100.in-addr.arpa"},
		{"revert", "meshdns0"},
	}
	if !equalCommandCalls(runner.calls, want) {
		t.Fatalf("command calls = %v, want %v", runner.calls, want)
	}
}

func testDNSConfig() DNSConfig {
	return DNSConfig{
		Endpoint: DNSEndpoint{
			InterfaceName: "meshdns0",
			Resolver:      netip.MustParseAddrPort("192.0.2.53:1053"),
		},
		SearchDomains: []string{"mesh.example"},
		RouteDomains:  []string{".", "64.100.in-addr.arpa"},
		DefaultRoute:  true,
	}
}

type fakeCommandRunner struct {
	calls  [][]string
	failAt int
}

func (f *fakeCommandRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{}, args...))
	if f.failAt != 0 && len(f.calls) == f.failAt {
		return []byte("simulated failure"), errors.New("exit status 1")
	}

	return nil, nil
}

func equalCommandCalls(left, right [][]string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !slices.Equal(left[index], right[index]) {
			return false
		}
	}

	return true
}

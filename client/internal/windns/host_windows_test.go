//go:build windows

package windns

import (
	"context"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"

	"meshtransit.net/client/internal/dnsconfig"
	"meshtransit.net/client/internal/networkmap"
)

// TestNRPTEndToEnd installs the real rule and resolver, resolves a mesh name
// through the Windows DNS client, and checks that closing removes the rule.
// It changes machine DNS policy, so it runs only when asked to, elevated,
// with the MeshTransit service stopped (both use the same rule and address).
func TestNRPTEndToEnd(t *testing.T) {
	if os.Getenv("MESHTRANSIT_WINDOWS_DNS_TEST") != "1" {
		t.Skip("set MESHTRANSIT_WINDOWS_DNS_TEST=1 to change this machine's DNS policy")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	resolver, err := dnsconfig.NewServer(Opener{})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	host, err := NewNRPTHost(resolver, nil)
	if err != nil {
		t.Fatalf("NewNRPTHost() error = %v", err)
	}
	manager, err := dnsconfig.NewManager(resolver, host)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer func() { _ = manager.Close(context.WithoutCancel(ctx)) }()
	want := netip.MustParseAddr("100.64.9.9")
	snapshot := networkmap.Snapshot{Revision: 1, DNS: &networkmap.DNSConfig{
		Routes:  []networkmap.DNSRoute{{Suffix: "c2h-test.mesh"}},
		Records: []networkmap.DNSRecord{{Name: "probe.c2h-test.mesh", Type: networkmap.DNSRecordA, Address: want}},
	}}
	configured, err := manager.Apply(ctx, snapshot)
	if err != nil || !configured {
		t.Fatalf("Apply() = %v, %v", configured, err)
	}
	stored, found, err := readRule(localPolicyKey)
	if err != nil || !found || !slices.Equal(stored.Namespaces, []string{".c2h-test.mesh"}) {
		t.Fatalf("stored rule = %+v, %v, %v", stored, found, err)
	}

	if groupPolicyPresent() {
		// The DNS client reads Group Policy rules only when machine policy
		// is applied with NRPT settings, which a test machine cannot cause.
		if _, found, err := readRule(groupPolicyKey); err != nil || !found {
			t.Fatalf("rule under the Group Policy key: found %v, error %v", found, err)
		}
		t.Log("Group Policy NRPT is in force; skipping resolution")
	} else {
		assertResolves(ctx, t, "probe.c2h-test.mesh", want)
	}

	if err := manager.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	for _, base := range []string{localPolicyKey, groupPolicyKey} {
		if _, found, err := readRule(base); err != nil || found {
			t.Fatalf("rule under %s after Close: found %v, error %v", base, found, err)
		}
	}
}

func assertResolves(ctx context.Context, t *testing.T, name string, want netip.Addr) {
	t.Helper()
	addresses, err := lookupUntil(ctx, name)
	if err != nil {
		t.Fatalf("resolving through the DNS client: %v", err)
	}
	if !slices.Contains(addresses, want.String()) {
		t.Fatalf("addresses = %v, want %s", addresses, want)
	}
}

// lookupUntil retries while the DNS client picks up the new policy.
func lookupUntil(ctx context.Context, name string) ([]string, error) {
	var lastErr error
	for range 20 {
		addresses, err := net.DefaultResolver.LookupHost(ctx, name)
		if err == nil {
			return addresses, nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}

	return nil, lastErr
}

// TestNRPTUnderGroupPolicy checks that the rule also goes under the Group
// Policy key while that key exists, and that Apply writes it again after
// policy processing removed it. It needs the same opt-in as TestNRPTEndToEnd
// and creates an empty Group Policy key, removed afterwards, if there is none.
func TestNRPTUnderGroupPolicy(t *testing.T) {
	if os.Getenv("MESHTRANSIT_WINDOWS_DNS_TEST") != "1" {
		t.Skip("set MESHTRANSIT_WINDOWS_DNS_TEST=1 to change this machine's DNS policy")
	}
	if !groupPolicyPresent() {
		createdKeys := createGroupPolicyKey(t)
		defer func() {
			for _, created := range createdKeys {
				if err := registry.DeleteKey(registry.LOCAL_MACHINE, created); err != nil {
					t.Errorf("removing %s: %v", created, err)
				}
			}
		}()
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	resolver, err := dnsconfig.NewServer(Opener{})
	if err != nil {
		t.Fatalf("NewServer() error = %v", err)
	}
	host, err := NewNRPTHost(resolver, nil)
	if err != nil {
		t.Fatalf("NewNRPTHost() error = %v", err)
	}
	manager, err := dnsconfig.NewManager(resolver, host)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	defer func() { _ = manager.Close(context.WithoutCancel(ctx)) }()
	snapshot := networkmap.Snapshot{Revision: 1, DNS: &networkmap.DNSConfig{
		Routes: []networkmap.DNSRoute{{Suffix: "c2h-test.mesh"}},
		Records: []networkmap.DNSRecord{{
			Name: "probe.c2h-test.mesh", Type: networkmap.DNSRecordA, Address: netip.MustParseAddr("100.64.9.9"),
		}},
	}}
	if _, err := manager.Apply(ctx, snapshot); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	assertStored(t, true)
	if err := deleteRule(groupPolicyKey); err != nil {
		t.Fatalf("deleteRule() error = %v", err)
	}
	snapshot.Revision = 2
	if _, err := manager.Apply(ctx, snapshot); err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}
	assertStored(t, true)
	if err := manager.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	assertStored(t, false)
}

// createGroupPolicyKey creates the Group Policy NRPT key and returns the keys
// it created, deepest first.
func createGroupPolicyKey(t *testing.T) []string {
	t.Helper()
	parent := `SOFTWARE\Policies\Microsoft\Windows NT\DNSClient`
	var created []string
	for _, path := range []string{parent, groupPolicyKey} {
		key, existed, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			t.Fatalf("creating %s: %v", path, err)
		}
		_ = key.Close()
		if !existed {
			created = append([]string{path}, created...)
		}
	}

	return created
}

func assertStored(t *testing.T, want bool) {
	t.Helper()
	for _, base := range []string{localPolicyKey, groupPolicyKey} {
		if _, found, err := readRule(base); err != nil || found != want {
			t.Fatalf("rule under %s: found %v, error %v; want %v", base, found, err, want)
		}
	}
}

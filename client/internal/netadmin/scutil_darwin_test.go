package netadmin

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

type recordingScriptRunner struct {
	scripts []string
	output  string
	err     error
}

func (r *recordingScriptRunner) RunScript(_ context.Context, path, script string) ([]byte, error) {
	if path != DefaultScutilPath {
		return nil, errors.New("unexpected scutil path")
	}
	r.scripts = append(r.scripts, script)
	return []byte(r.output), r.err
}

func testDNSConfig() DNSConfig {
	return DNSConfig{
		Endpoint: DNSEndpoint{
			InterfaceName: "utun7",
			Resolver:      netip.MustParseAddrPort("192.0.2.53:1053"),
		},
		SearchDomains: []string{"consumer.mesh"},
		RouteDomains:  []string{"shared.mesh", "64.100.in-addr.arpa"},
	}
}

func TestScutilApplyScript(t *testing.T) {
	t.Parallel()
	script, err := scutilApplyScript(testDNSConfig())
	if err != nil {
		t.Fatal(err)
	}
	want := "d.init\n" +
		"d.add ServerAddresses * 192.0.2.53\n" +
		"d.add ServerPort # 1053\n" +
		"d.add SupplementalMatchDomains * shared.mesh 64.100.in-addr.arpa consumer.mesh\n" +
		"d.add SearchDomains * consumer.mesh\n" +
		"set State:/Network/Service/net.meshtransit.dns/DNS\n"
	if script != want {
		t.Fatalf("script =\n%s\nwant\n%s", script, want)
	}
	injected := testDNSConfig()
	injected.SearchDomains = []string{"a.mesh\nremove State:/Network/Global/DNS"}
	if _, err := scutilApplyScript(injected); err == nil {
		t.Fatal("scutilApplyScript accepted a domain with a newline")
	}
}

func TestScutilConfiguratorAppliesResetsAndRollsBack(t *testing.T) {
	t.Parallel()
	runner := &recordingScriptRunner{}
	configurator := &scutilConfigurator{path: DefaultScutilPath, runner: runner}
	if err := configurator.Apply(t.Context(), testDNSConfig()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if err := configurator.Reset(t.Context(), DNSEndpoint{}); err != nil {
		t.Fatalf("Reset() error = %v", err)
	}
	if len(runner.scripts) != 2 || runner.scripts[1] != "remove "+scutilDNSKey+"\n" {
		t.Fatalf("scripts = %q", runner.scripts)
	}

	failing := &recordingScriptRunner{output: "No such key"}
	configurator = &scutilConfigurator{path: DefaultScutilPath, runner: failing}
	if err := configurator.Apply(t.Context(), testDNSConfig()); err == nil {
		t.Fatal("Apply() ignored scutil output")
	}
	if len(failing.scripts) != 2 || !strings.HasPrefix(failing.scripts[1], "remove ") {
		t.Fatalf("failed Apply did not roll back: %q", failing.scripts)
	}

	allNames := testDNSConfig()
	allNames.RouteDomains = append(allNames.RouteDomains, ".")
	allNames.DefaultRoute = true
	if err := (&scutilConfigurator{path: DefaultScutilPath, runner: &recordingScriptRunner{}}).Apply(t.Context(), allNames); err == nil {
		t.Fatal("Apply() accepted DNS for all names")
	}
}

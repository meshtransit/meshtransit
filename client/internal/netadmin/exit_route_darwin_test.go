//go:build darwin

package netadmin

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"meshtransit.net/client/internal/hostroute"
)

func TestPfExitRulesLetOutOnlyTheExceptions(t *testing.T) {
	t.Parallel()
	rules := pfExitRules("utun7", 270, []netip.Prefix{netip.MustParsePrefix("192.168.1.9/24")})
	for _, want := range []string{
		"pass out quick on lo0 all flags any\n",
		"pass out quick on utun7 all flags any\n",
		"pass out quick proto { tcp udp } user 270 flags any\n",
		"pass out quick inet proto udp from any port 68 to any port 67\n",
		"pass out quick inet to { 192.168.1.0/24 }\n",
		"pass out quick inet6 to fe80::/10\n",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("rules lack %q:\n%s", want, rules)
		}
	}
	if pfctl, err := exec.LookPath("/sbin/pfctl"); err == nil {
		// Parsing needs no privilege: the anchor must load as written.
		file := filepath.Join(t.TempDir(), "rules.conf")
		if err := os.WriteFile(file, []byte(rules), 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.CommandContext(t.Context(), pfctl, "-nf", file).CombinedOutput(); err != nil { //nolint:gosec // G204: test
			t.Fatalf("pfctl rejects the rules: %v\n%s", err, output)
		}
	}
	if !strings.HasSuffix(rules, "block drop out quick all\n") {
		t.Fatalf("rules do not end blocking:\n%s", rules)
	}
	closed := pfExitRules("", 270, nil)
	if strings.Contains(closed, "utun") || strings.Contains(closed, "192.168") {
		t.Fatalf("without a utun or LAN the rules let them out:\n%s", closed)
	}
}

type pfctlCall struct {
	args  string
	stdin string
}

func TestDarwinExitKillSwitchHoldsOnePfReference(t *testing.T) {
	t.Parallel()
	var calls []pfctlCall
	configurer := &darwinExitRouteConfigurer{
		uid: 270, pfctl: DefaultPfctlPath, tokenPath: filepath.Join(t.TempDir(), "exit-pf-token"),
		lan: func() []netip.Prefix { return nil },
		run: func(_ context.Context, _ string, args []string, stdin string) ([]byte, error) {
			calls = append(calls, pfctlCall{args: strings.Join(args, " "), stdin: stdin})
			if args[0] == "-E" {
				return []byte("pf enabled\nToken : 1234\n"), nil
			}
			if strings.Join(args, " ") == "-s info" {
				return []byte("Status: Enabled for 0 days\n"), nil
			}
			return nil, nil
		},
	}
	// Without a utun the host is closed: no route is touched.
	for range 2 {
		if err := configurer.Replace("", false, false); err != nil {
			t.Fatal(err)
		}
	}
	enables := 0
	for _, call := range calls {
		if call.args == "-E" {
			enables++
		}
	}
	if enables != 1 {
		t.Fatalf("pf enabled %d times, want once: %+v", enables, calls)
	}
	last := calls[len(calls)-1]
	if last.args != "-a "+exitAnchor+" -f -" || !strings.Contains(last.stdin, "block drop out quick all") {
		t.Fatalf("last pfctl call = %+v", last)
	}
	if token, err := os.ReadFile(configurer.tokenPath); err != nil || strings.TrimSpace(string(token)) != "1234" {
		t.Fatalf("token = %q, %v", token, err)
	}
	calls = nil
	if err := configurer.Clear(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || calls[0].args != "-a "+exitAnchor+" -F rules" || calls[1].args != "-X 1234" {
		t.Fatalf("clear ran %+v", calls)
	}
	if _, err := os.Stat(configurer.tokenPath); !os.IsNotExist(err) {
		t.Fatalf("token kept after clear: %v", err)
	}
	if err := configurer.Replace("en0", false, false); err == nil {
		t.Fatal("Replace() accepted a target that is no utun")
	}
}

func TestPhysicalDefaultsSkipMeshnetdsAndScopedRoutes(t *testing.T) {
	names := map[int]string{14: "en0", 9: "en1", 22: "utun4", 30: "utun0", 31: "ppp0"}
	previous := interfaceName
	interfaceName = func(index int) string { return names[index] }
	t.Cleanup(func() { interfaceName = previous })
	gateway := &route.Inet4Addr{IP: [4]byte{172, 20, 10, 1}}
	table := []hostroute.Route{
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC, Index: 14, Gateway: gateway},
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC, Index: 30, Gateway: gateway},
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC, Index: 31, Gateway: gateway},
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_IFSCOPE, Index: 9, Gateway: gateway},
		{Prefix: netip.MustParsePrefix("0.0.0.0/1"), Flags: unix.RTF_UP | unix.RTF_STATIC | hostroute.ExitMark, Index: 22, Gateway: &route.LinkAddr{Index: 22}},
		{
			Prefix: netip.MustParsePrefix("0.0.0.0/0"), Index: 14, Gateway: gateway,
			Flags: unix.RTF_UP | unix.RTF_GATEWAY | unix.RTF_STATIC | unix.RTF_IFSCOPE | hostroute.ExitMark,
		},
	}
	defaults := physicalDefaults(table)
	if len(defaults) != 2 || defaults[0].Index != 14 || defaults[1].Index != 31 {
		t.Fatalf("physicalDefaults() = %+v, want the unscoped en0 and ppp0 defaults only", defaults)
	}
	if !table[5].ExitScoped() || table[0].ExitScoped() || table[3].ExitScoped() {
		t.Fatal("ExitScoped() must match only meshnetd's scoped default")
	}
}

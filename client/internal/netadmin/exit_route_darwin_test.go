//go:build darwin

package netadmin

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPfExitRulesLetOutOnlyTheExceptions(t *testing.T) {
	t.Parallel()
	rules := pfExitRules("utun7", 270, []netip.Prefix{netip.MustParsePrefix("192.168.1.9/24")})
	for _, want := range []string{
		"pass out quick on lo0 all\n",
		"pass out quick on utun7 all\n",
		"pass out quick proto { tcp udp } user 270\n",
		"pass out quick inet proto udp from any port 68 to any port 67\n",
		"pass out quick inet to { 192.168.1.0/24 }\n",
		"pass out quick inet6 to fe80::/10\n",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("rules lack %q:\n%s", want, rules)
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

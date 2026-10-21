//go:build darwin

package netadmin

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The window's rules let TCP out by the physical interface from its own
// address to ports 80 and 443, and to the portal, without state, before
// the drop, and pfctl accepts them.
func TestPfCaptiveRulesOpenOnlyTheWindow(t *testing.T) {
	t.Parallel()
	captive := pfCaptiveRules([]string{"en0"}, [2]netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:8880")})
	rules := pfExitRules("utun7", 270, nil, captive)
	for _, want := range []string{
		`pass out quick on en0 inet proto tcp from (en0) to any port { 80 443 } no state label "meshtransit-captive"` + "\n",
		`pass out quick on en0 inet proto tcp from (en0) to 10.0.0.1 port 8880 no state label "meshtransit-captive"` + "\n",
		`pass out quick on en0 inet6 proto tcp from (en0) to any port { 80 443 } no state label "meshtransit-captive"` + "\n",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("rules lack %q:\n%s", want, rules)
		}
	}
	if strings.Contains(rules, "inet6 proto tcp from (en0) to 10.0.0.1") {
		t.Errorf("an IPv4 portal in an IPv6 rule:\n%s", rules)
	}
	if !strings.HasSuffix(rules, captive+"block drop out quick all\n") {
		t.Fatalf("the window's rules do not come right before the drop:\n%s", rules)
	}
	if pfctl, err := exec.LookPath("/sbin/pfctl"); err == nil {
		file := filepath.Join(t.TempDir(), "rules.conf")
		if err := os.WriteFile(file, []byte(rules), 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.CommandContext(t.Context(), pfctl, "-nf", file).CombinedOutput(); err != nil { //nolint:gosec // G204: test
			t.Fatalf("pfctl rejects the rules: %v\n%s", err, output)
		}
	}
}

// A window keeps what ends it without the helper (the kill switch without
// its rules) and starts its timer once; closing it loads the kill switch
// without its rules and forgets the state.
func TestDarwinCaptiveWindowKeepsItsEnd(t *testing.T) {
	t.Parallel()
	var loaded []string
	var spawned []string
	dir := t.TempDir()
	configurer := &darwinExitRouteConfigurer{
		uid: 270, pfctl: DefaultPfctlPath, tokenPath: filepath.Join(dir, "exit-pf-token"),
		lan: func() []netip.Prefix { return nil }, interfaces: func() []string { return []string{"en0"} },
		run: func(_ context.Context, _ string, args []string, stdin string) ([]byte, error) {
			switch strings.Join(args, " ") {
			case "-E":
				return []byte("Token : 1234\n"), nil
			case "-s info":
				return []byte("Status: Enabled\n"), nil
			case "-a " + exitAnchor + " -f -":
				loaded = append(loaded, stdin)
			}
			return nil, nil
		},
	}
	configurer.holesPath = filepath.Join(dir, "captive-holes.json")
	configurer.spawnExpiry = func(id string, remaining time.Duration) error {
		spawned = append(spawned, id+" "+remaining.String())
		return nil
	}
	window := &exitCaptive{ID: strings.Repeat("ab", 16), Remaining: 2 * time.Minute}
	for range 2 {
		opened, err := configurer.Replace("", false, false, window)
		if err != nil || opened != "en0" {
			t.Fatalf("Replace() with a window = %q, %v", opened, err)
		}
	}
	if len(spawned) != 1 || spawned[0] != window.ID+" 2m0s" {
		t.Fatalf("timers started: %v", spawned)
	}
	if last := loaded[len(loaded)-1]; !strings.Contains(last, captiveLabel) {
		t.Fatalf("the window's rules were not loaded:\n%s", last)
	}
	encoded, err := os.ReadFile(configurer.holesPath)
	if err != nil {
		t.Fatal(err)
	}
	var state darwinCaptiveState
	if err := json.Unmarshal(encoded, &state); err != nil || state.ID != window.ID ||
		strings.Contains(state.Rules, captiveLabel) || !strings.HasSuffix(state.Rules, "block drop out quick all\n") ||
		time.Until(state.Until) > 2*time.Minute {
		t.Fatalf("state = %+v, %v", state, err)
	}
	if _, err := readCaptiveState(configurer.holesPath); os.Geteuid() != 0 && err == nil {
		t.Fatal("a state file root does not own alone was read")
	}

	if _, err := configurer.Replace("", false, false, nil); err != nil {
		t.Fatal(err)
	}
	if last := loaded[len(loaded)-1]; strings.Contains(last, captiveLabel) {
		t.Fatalf("the window's rules outlived it:\n%s", last)
	}
	if _, err := os.Stat(configurer.holesPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the window's state outlived it: %v", err)
	}
	// No physical default route: nothing opens.
	configurer.interfaces = func() []string { return nil }
	if opened, err := configurer.Replace("", false, false, window); err != nil || opened != "" ||
		strings.Contains(loaded[len(loaded)-1], captiveLabel) {
		t.Fatalf("a window without an interface opened %q, %v", opened, err)
	}
}

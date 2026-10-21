package routescli

import (
	"bytes"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"meshtransit.net/client/internal/routesettings"
)

func TestChangeRouteSettings(t *testing.T) {
	t.Parallel()
	settings := routesettings.Settings{}
	steps := []struct {
		command  string
		operands []string
	}{
		{"accept", []string{"on"}},
		{"router-mode", []string{"on"}},
		{"advertise", []string{"10.20.0.0/16", "2001:db8::/48", "10.20.0.0/16"}},
		{"withdraw", []string{"2001:db8::/48"}},
	}
	for _, step := range steps {
		var err error
		if settings, err = changeRouteSettings(settings, step.command, step.operands); err != nil {
			t.Fatalf("%s: %v", step.command, err)
		}
	}
	if !settings.AcceptRoutes || !settings.RouterMode || settings.AcceptPublicRoutes ||
		!slices.Equal(settings.AdvertiseRoutes, []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}) {
		t.Fatalf("settings = %+v", settings)
	}
	for _, bad := range []struct {
		command  string
		operands []string
	}{
		{"accept", []string{"yes"}},
		{"advertise", nil},
		{"advertise", []string{"10.20.0.1/16"}},
		{"advertise", []string{"0.0.0.0/0"}},
		{"enable", nil},
	} {
		if _, err := changeRouteSettings(settings, bad.command, bad.operands); err == nil {
			t.Errorf("%s %v was accepted", bad.command, bad.operands)
		}
	}
}

func TestRunRoutesShowsAMissingFileAsOff(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	path := filepath.Join(t.TempDir(), "routes.json")
	command := Command{Program: "meshnetd", Privilege: "root privileges", Privileged: func() bool { return false }}
	if code := command.Run([]string{"--routes-file", path, "show"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "accept: off") || !strings.Contains(stdout.String(), "router-mode: off") {
		t.Fatalf("output = %q", stdout.String())
	}
}

func TestRunRoutesRefusesAnUnprivilegedChange(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	path := filepath.Join(t.TempDir(), "routes.json")
	command := Command{Program: "meshd", Privilege: "administrator rights", Privileged: func() bool { return false }}
	if code := command.Run([]string{"--routes-file", path, "accept", "on"}, &stdout, &stderr); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "meshd: administrator rights are required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if settings, err := routesettings.Load(path); err != nil || settings.AcceptRoutes {
		t.Fatalf("settings after a refused change = %+v, %v", settings, err)
	}
}

func TestChangeExitSettings(t *testing.T) {
	t.Parallel()
	settings := routesettings.Settings{}
	for _, step := range []struct {
		command  string
		operands []string
	}{
		{"exit-mode", []string{"on"}},
		{"exit-smtp", []string{"on"}},
		{"exit-conntrack-max", []string{"8192"}},
		{"exit-max-consumers", []string{"32"}},
	} {
		var err error
		if settings, err = changeRouteSettings(settings, step.command, step.operands); err != nil {
			t.Fatalf("%s: %v", step.command, err)
		}
	}
	if !settings.ExitMode || !settings.ExitSMTPAllowed || settings.ExitConntrackPerConsumerMax != 8192 ||
		settings.ExitMaxConsumers != 32 {
		t.Fatalf("settings = %+v", settings)
	}
	for _, bad := range []struct {
		command  string
		operands []string
	}{
		{"exit-mode", []string{"maybe"}},
		{"exit-conntrack-max", []string{"10"}},
		{"exit-conntrack-max", []string{"-1"}},
		{"exit-max-consumers", []string{"many"}},
		{"exit-max-consumers", []string{"5000"}},
	} {
		if _, err := changeRouteSettings(settings, bad.command, bad.operands); err == nil {
			t.Errorf("%s %v was accepted", bad.command, bad.operands)
		}
	}
}

func TestChangeExitUseSettings(t *testing.T) {
	t.Parallel()
	settings := routesettings.Settings{}
	for _, step := range []struct {
		command  string
		operands []string
	}{
		{"exit-use", []string{"Office egress"}},
		{"exit-allow-lan", []string{"on"}},
		{"exit-allow-managed", []string{"on"}},
	} {
		var err error
		if settings, err = changeRouteSettings(settings, step.command, step.operands); err != nil {
			t.Fatalf("%s: %v", step.command, err)
		}
	}
	if settings.ExitUse != "Office egress" || !settings.ExitAllowLAN || !settings.ExitAllowManaged {
		t.Fatalf("settings = %+v", settings)
	}
	if off, err := changeRouteSettings(settings, "exit-use", []string{"off"}); err != nil || off.ExitUse != "" {
		t.Fatalf("exit-use off = %+v, %v", off, err)
	}
	for _, bad := range [][]string{nil, {""}, {" padded"}, {"a\nb"}} {
		if _, err := changeRouteSettings(settings, "exit-use", bad); err == nil {
			t.Errorf("exit-use %q was accepted", bad)
		}
	}
}

func TestRunRoutesElevatesOnlyAValidChange(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "routes.json")
	elevated := 0
	command := Command{
		Program: "meshctl", Privilege: "root privileges", Privileged: func() bool { return false },
		Elevate: func() int { elevated++; return 7 },
	}
	var stdout, stderr bytes.Buffer
	if code := command.Run([]string{"--routes-file", path, "exit-use", "World"}, &stdout, &stderr); code != 7 ||
		elevated != 1 {
		t.Fatalf("valid change = %d, elevated %d", code, elevated)
	}
	// A typo fails here, before any password is asked for.
	if code := command.Run([]string{"--routes-file", path, "exit-use"}, &stdout, &stderr); code != 2 || elevated != 1 {
		t.Fatalf("malformed change = %d, elevated %d", code, elevated)
	}
	// Reading needs nothing.
	if code := command.Run([]string{"--routes-file", path, "show"}, &stdout, &stderr); code != 0 || elevated != 1 {
		t.Fatalf("show = %d, elevated %d", code, elevated)
	}
	// Privileged, it changes the file itself.
	command.Privileged = func() bool { return true }
	stdout.Reset()
	if code := command.Run([]string{"--routes-file", path, "exit-use", "World"}, &stdout, &stderr); code != 0 ||
		elevated != 1 || !strings.Contains(stdout.String(), "exit-use: World") {
		t.Fatalf("privileged change = %d, elevated %d: %s", code, elevated, stdout.String())
	}
}

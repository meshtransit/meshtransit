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

//go:build integration && linux

package netadmin

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestKernelExitCaptiveWindowIntegration opens a captive portal window on a
// real kernel: the host's own TCP to ports 80 and 443 (and the portal's)
// leaves by the default route's interface from its address, nothing else
// does, the kernel drops the holes when the window's time is up, also
// without the helper, and a hole no window opened is seen as tampering.
func TestKernelExitCaptiveWindowIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft is required to read the rules back")
	}
	ip, err := exec.LookPath("ip")
	if err != nil {
		t.Skip("ip is required to ask the kernel for routes")
	}
	nc, err := exec.LookPath("nc")
	if err != nil {
		t.Skip("nc is required to send packets")
	}
	defaultRoute, err := exec.Command(ip, "-4", "route", "show", "default").CombinedOutput()
	fields := strings.Fields(string(defaultRoute))
	if err != nil || len(fields) < 5 || fields[1] != "via" || fields[3] != "dev" {
		t.Skipf("an IPv4 default route via a gateway is required: %s", defaultRoute)
	}
	gateway, physical := fields[2], fields[4]
	const name = "meshit4"
	file, _, err := (kernelTUNCreator{}).Open(name, 1280, 0,
		[]netip.Prefix{netip.MustParsePrefix("100.127.255.242/32")}, []netip.Prefix{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })
	options := RoutedOptions{
		SettingsPath: "/etc/meshtransit/routes.json", Table: 5267, Priority: 5400,
		ExitTable: 5292, ExitPriority: 5402, ExitNftTable: "meshtransit_kill_cp",
		StatePath: filepath.Join(t.TempDir(), "router-state.json"),
	}
	configurer := newKernelExitRouteConfigurer(options, 4243)
	t.Cleanup(func() { _ = configurer.Clear() })
	portal := netip.MustParseAddrPort("10.255.0.1:8880")
	opened, err := configurer.Replace(name, false, false,
		&exitCaptive{Remaining: 3 * time.Second, Portals: [2]netip.AddrPort{portal}})
	if err != nil || opened != physical {
		t.Fatalf("Replace() with a window = %q, %v; want %q", opened, err, physical)
	}
	run := func(command string, args ...string) string {
		t.Helper()
		output, _ := exec.Command(command, args...).CombinedOutput()
		return string(output)
	}
	rules := run(ip, "-4", "rule", "show", "priority", "5404")
	for _, want := range []string{
		"iif lo ipproto %s dport 80 lookup main", "iif lo ipproto %s dport 443 lookup main",
		"to 10.255.0.1 iif lo ipproto %s dport 8880 lookup main",
	} {
		// iproute2 names the protocol from /etc/protocols when it has one.
		if !strings.Contains(rules, fmt.Sprintf(want, "tcp")) && !strings.Contains(rules, fmt.Sprintf(want, "ipproto-6")) {
			t.Errorf("window rules lack %q:\n%s", want, rules)
		}
	}
	if got := run(ip, "route", "get", "1.1.1.1", "ipproto", "6", "dport", "443", "uid", "0"); !strings.Contains(got, "dev "+physical) {
		t.Errorf("HTTPS in the window: %s", got)
	}
	if got := run(ip, "route", "get", "1.1.1.1", "ipproto", "6", "dport", "22", "uid", "0"); !strings.Contains(got, "dev "+name) {
		t.Errorf("SSH in the window left the mesh: %s", got)
	}
	sets := run(nft, "list", "set", "inet", "meshtransit_kill_cp", "captive4") +
		run(nft, "list", "set", "inet", "meshtransit_kill_cp", "portal4")
	for _, want := range []string{`"` + physical + `" . `, " . 80 timeout", " . 443 timeout", " . 10.255.0.1 . 8880 timeout"} {
		if !strings.Contains(sets, want) {
			t.Errorf("window sets lack %q:\n%s", want, sets)
		}
	}
	// Port 80 leaves and is answered (refused by the gateway, or served);
	// port 22 to the same host goes into the mesh and nowhere.
	reach := func(port string) string {
		output, _ := exec.Command(nc, "-z", "-v", "-w", "1", gateway, port).CombinedOutput()
		return string(output)
	}
	if got := reach("80"); strings.Contains(got, "timed out") {
		t.Errorf("port 80 did not leave in the window: %s", got)
	}
	if got := reach("22"); !strings.Contains(got, "timed out") {
		t.Errorf("port 22 left in the window: %s", got)
	}
	if present, err := configurer.Present(); err != nil || !present {
		t.Fatalf("Present() in the window = %t, %v", present, err)
	}
	// The kernel ends the window by itself: port 80 goes nowhere, closed.
	time.Sleep(3500 * time.Millisecond)
	if left := run(nft, "list", "set", "inet", "meshtransit_kill_cp", "captive4"); strings.Contains(left, " . 80") {
		t.Errorf("elements outlived the window:\n%s", left)
	}
	if got := reach("80"); !strings.Contains(got, "timed out") {
		t.Errorf("port 80 left after the window: %s", got)
	}
	if present, err := configurer.Present(); err != nil || !present {
		t.Fatalf("Present() after the kernel ended the window = %t, %v", present, err)
	}
	// A hole no window opened is tampering.
	if output, err := exec.Command(nft, "add", "element", "inet", "meshtransit_kill_cp", "captive4",
		`{ "`+physical+`" . 192.0.2.1 . 22 timeout 1m }`).CombinedOutput(); err != nil {
		t.Fatalf("adding a hole: %v: %s", err, output)
	}
	if present, err := configurer.Present(); err != nil || present {
		t.Errorf("a hole no window opened: Present() = %t, %v", present, err)
	}
	// Closed: no rule sends ports 80 and 443 to the main table.
	if _, err := configurer.Replace(name, false, false, nil); err != nil {
		t.Fatal(err)
	}
	if rules := run(ip, "-4", "rule", "show", "priority", "5404"); strings.Contains(rules, "dport") {
		t.Errorf("window rules outlived the window:\n%s", rules)
	}
	if got := run(ip, "route", "get", "1.1.1.1", "ipproto", "6", "dport", "443", "uid", "0"); !strings.Contains(got, "dev "+name) {
		t.Errorf("HTTPS after the window: %s", got)
	}
}

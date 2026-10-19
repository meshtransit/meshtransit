//go:build integration && linux

package netadmin

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"meshtransit.net/client/internal/routesettings"
)

// TestKernelServedConfigurerIntegration forwards into a served prefix on a
// real kernel and reads back what it installed: the host's forwarding
// settings, restored afterwards, and the router table.
func TestKernelServedConfigurerIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft is required to read the rules back")
	}
	const name, lan = "meshit2", "lanit0"
	file, _, err := (kernelTUNCreator{}).Open(name, 1280, 0,
		[]netip.Prefix{netip.MustParsePrefix("100.127.255.240/32")}, []netip.Prefix{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: lan}}
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(dummy) })
	address, _ := netlink.ParseAddr("10.200.5.1/24")
	if err := netlink.AddrAdd(dummy, address); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(dummy); err != nil {
		t.Fatal(err)
	}
	sysctl := func(path string) string {
		t.Helper()
		value, err := readSysctl(filepath.Join("/proc/sys", path))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	for _, path := range []string{"net/ipv4/ip_forward", "net/ipv4/conf/" + name + "/forwarding", "net/ipv4/conf/" + lan + "/forwarding"} {
		if err := writeSysctl(filepath.Join("/proc/sys", path), "0"); err != nil {
			t.Fatal(err)
		}
	}
	// A prefix the host reaches only through the mesh has no route out.
	tunLink, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: tunLink.Attrs().Index,
		Dst:       prefixIPNet(netip.MustParsePrefix("10.202.0.0/24")), Scope: netlink.SCOPE_LINK,
	}); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "router-state.json")
	configurer := kernelServedConfigurer{table: "meshtransit_it", statePath: state, sysctlRoot: "/proc/sys"}
	t.Cleanup(func() { _ = configurer.Clear() })
	served, refused, err := configurer.ReplaceServed(name, []netip.Prefix{netip.MustParsePrefix("100.127.255.240/32")}, 1280,
		[]routesettings.ServedEntry{
			{Prefix: netip.MustParsePrefix("10.200.5.0/24"), Masquerade: true},
			{Prefix: netip.MustParsePrefix("10.202.0.0/24")}, // routed into the mesh only
			// Adjacent to the first, and at the top of the address space:
			// one merged range, and one without an end.
			{Prefix: netip.MustParsePrefix("10.200.4.0/24"), Masquerade: true},
			{Prefix: netip.MustParsePrefix("255.255.255.0/24")},
		})
	if err != nil {
		t.Fatalf("ReplaceServed() error = %v", err)
	}
	if len(served) != 3 || len(refused) != 1 || refused[0].Reason != ReasonNoRoute {
		t.Fatalf("served = %v, refused = %v", served, refused)
	}
	// The kernel checks the interface a packet arrives on: the TUN and the
	// way back forward, the host as a whole does not.
	if sysctl("net/ipv4/conf/"+name+"/forwarding") != "1" || sysctl("net/ipv4/conf/"+lan+"/forwarding") != "1" ||
		sysctl("net/ipv4/ip_forward") != "0" {
		t.Fatal("forwarding is not on exactly for the tun and the lan")
	}
	listing, err := exec.Command(nft, "list", "table", "inet", "meshtransit_it").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list: %v: %s", err, listing)
	}
	text := string(listing)
	for _, want := range []string{
		"10.200.4.0/23", "255.255.255.0/24", "masquerade", "maxseg size", "ct state established,related accept",
		`iifname "` + name + `" drop`, `oifname "` + name + `" drop`, `iifname "` + lan + `"`, "100.127.255.240",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("router table lacks %q:\n%s", want, text)
		}
	}
	t.Log(text)
	if present, err := configurer.Present(); err != nil || !present {
		t.Fatalf("Present() = %t, %v", present, err)
	}
	// A setting something reset is set again by the next request.
	if err := writeSysctl("/proc/sys/net/ipv4/conf/"+lan+"/forwarding", "0"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := configurer.ReplaceServed(name, []netip.Prefix{netip.MustParsePrefix("100.127.255.240/32")}, 1280,
		served); err != nil {
		t.Fatal(err)
	}
	if sysctl("net/ipv4/conf/"+lan+"/forwarding") != "1" {
		t.Fatal("reset forwarding was not set again")
	}
	// A helper that crashed leaves its state; the next one restores it.
	restarted := kernelServedConfigurer{table: "meshtransit_it", statePath: state, sysctlRoot: "/proc/sys"}
	if err := restarted.Clear(); err != nil {
		t.Fatalf("Clear() after a restart error = %v", err)
	}
	if sysctl("net/ipv4/conf/"+name+"/forwarding") != "0" || sysctl("net/ipv4/conf/"+lan+"/forwarding") != "0" {
		t.Fatal("forwarding was not restored")
	}
	if present, err := configurer.Present(); err != nil || present {
		t.Fatalf("Present() after Clear = %t, %v", present, err)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatalf("router state left behind: %v", err)
	}
	// A damaged state restores nothing, is set aside and stops nothing.
	if err := os.WriteFile(state, []byte(`{"ipv4_forwarding":{"../x":"0"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Clear(); err != nil {
		t.Fatalf("Clear() with a damaged state error = %v", err)
	}
	if _, err := os.Stat(state + ".bad"); err != nil {
		t.Fatalf("the damaged state was not set aside: %v", err)
	}
}

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
)

// TestKernelExitRouteConfigurerIntegration routes the host through an exit
// node on a real kernel and reads back the table, rules and kill switch,
// and where the kernel sends packets of meshd and of everyone else.
func TestKernelExitRouteConfigurerIntegration(t *testing.T) {
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
	const name, lan, bridge, port = "meshit3", "lanit3", "brit3", "vethit3"
	const meshdUID = 4242
	file, _, err := (kernelTUNCreator{}).Open(name, 1280, 0,
		[]netip.Prefix{netip.MustParsePrefix("100.127.255.241/32")}, []netip.Prefix{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })
	addLink := func(link netlink.Link, addresses ...string) {
		t.Helper()
		if err := netlink.LinkAdd(link); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = netlink.LinkDel(link) })
		for _, text := range addresses {
			address, _ := netlink.ParseAddr(text)
			if err := netlink.AddrAdd(link, address); err != nil {
				t.Fatal(err)
			}
		}
		if err := netlink.LinkSetUp(link); err != nil {
			t.Fatal(err)
		}
	}
	// A LAN with a private and a public subnet, and a container bridge whose
	// only port is a veth.
	addLink(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: lan}}, "192.168.77.2/24", "45.76.10.10/29")
	addLink(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: bridge}}, "172.31.250.1/24")
	veth := &netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: port}, PeerName: port + "p"}
	addLink(veth)
	bridgeLink, err := netlink.LinkByName(bridge)
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetMaster(veth, bridgeLink); err != nil {
		t.Fatal(err)
	}
	// A bridge over a VLAN of the LAN is a LAN, not a local bridge.
	lanLink, err := netlink.LinkByName(lan)
	if err != nil {
		t.Fatal(err)
	}
	vlan := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: lan + ".7", ParentIndex: lanLink.Attrs().Index}, VlanId: 7}
	addLink(vlan)
	addLink(&netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: "brlanit3"}}, "10.77.0.1/24")
	lanBridge, err := netlink.LinkByName("brlanit3")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetMaster(vlan, lanBridge); err != nil {
		t.Fatal(err)
	}
	options := RoutedOptions{
		SettingsPath: "/etc/meshtransit/routes.json", Table: 5267, Priority: 5400,
		ExitTable: 5291, ExitPriority: 5402, ExitNftTable: "meshtransit_kill_it",
		StatePath: filepath.Join(t.TempDir(), "router-state.json"),
	}
	validMarkBefore, err := readSysctl("/proc/sys/" + validMarkSetting)
	if err != nil {
		t.Fatal(err)
	}
	configurer := newKernelExitRouteConfigurer(options, meshdUID)
	t.Cleanup(func() { _ = configurer.Clear() })
	for range 2 { // installing twice changes nothing
		if err := configurer.Replace(name, true, true); err != nil {
			t.Fatalf("Replace() error = %v", err)
		}
	}
	routes := func() string {
		t.Helper()
		var lines []string
		for _, family := range []string{"-4", "-6"} {
			output, err := exec.Command(ip, family, "route", "show", "table", "5291").CombinedOutput()
			if err != nil {
				t.Fatalf("ip route show: %v: %s", err, output)
			}
			lines = append(lines, strings.TrimSpace(string(output)))
		}
		return strings.Join(lines, "\n")
	}
	table := routes()
	for _, want := range []string{
		"default dev " + name, "unreachable default", "192.168.77.0/24 dev " + lan,
		"172.31.250.0/24 dev " + bridge,
	} {
		if !strings.Contains(table, want) {
			t.Errorf("exit table lacks %q:\n%s", want, table)
		}
	}
	// Never a public subnet, whatever the interface holds.
	if strings.Contains(table, "45.76.10.8") || strings.Count(table, "default dev "+name) != 2 {
		t.Errorf("exit table:\n%s", table)
	}
	countRules := func(priority string) int {
		count := 0
		for _, family := range []string{"-4", "-6"} {
			output, err := exec.Command(ip, family, "rule", "show").CombinedOutput()
			if err != nil {
				t.Fatalf("ip rule show: %v: %s", err, output)
			}
			for line := range strings.SplitSeq(string(output), "\n") {
				if strings.HasPrefix(line, priority+":") {
					count++
				}
			}
		}
		return count
	}
	if countRules("5402") < 4 || countRules("5403") != 2 || countRules("5405") != 2 || countRules("5404") < 6 {
		t.Errorf("rules: 5402=%d 5403=%d 5404=%d 5405=%d", countRules("5402"), countRules("5403"),
			countRules("5404"), countRules("5405"))
	}
	// Everyone but meshd goes into the mesh; meshd keeps the host's routes.
	routeGet := func(args ...string) string {
		t.Helper()
		output, _ := exec.Command(ip, append([]string{"route", "get"}, args...)...).CombinedOutput()
		return string(output)
	}
	if got := routeGet("8.8.8.8", "uid", "0"); !strings.Contains(got, "dev "+name) {
		t.Errorf("root's packet to the Internet: %s", got)
	}
	if got := routeGet("8.8.8.8", "uid", "4242"); strings.Contains(got, "dev "+name) {
		t.Errorf("meshd's packet went into the mesh: %s", got)
	}
	if got := routeGet("192.168.77.9", "uid", "0"); !strings.Contains(got, "dev "+lan) {
		t.Errorf("the allowed LAN: %s", got)
	}
	ruleset, err := exec.Command(nft, "list", "table", "inet", "meshtransit_kill_it").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list: %v: %s", err, ruleset)
	}
	for _, want := range []string{
		"hook output", "hook forward", "hook prerouting", "type route", "meta skuid 4242 accept",
		`oifname "` + name + `" accept`, `oifname "` + bridge + `" accept`, "udp sport 68 udp dport 67",
		"ct direction original", "meta mark set meta mark | 0x20000000", "meta skuid 4242 ct mark set",
		"192.168.77.0/24", "224.0.0.0/24", "drop",
	} {
		if !strings.Contains(string(ruleset), want) {
			t.Errorf("kill switch lacks %q:\n%s", want, ruleset)
		}
	}
	// A socket bound to the LAN interface follows the main table, and the
	// kill switch drops what it sends to the Internet.
	if ping, err := exec.LookPath("ping"); err == nil {
		_ = exec.Command(ping, "-c", "1", "-W", "1", "-I", lan, "45.76.10.11").Run()
		chain, _ := exec.Command(nft, "list", "chain", "inet", "meshtransit_kill_it", "output").CombinedOutput()
		if strings.Contains(string(chain), "counter packets 0 ") {
			t.Errorf("the kill switch dropped nothing:\n%s", chain)
		}
	}
	if strings.Contains(string(ruleset), `oifname "brlanit3" accept`) {
		t.Error("a bridge over the LAN was taken for a local bridge")
	}
	if present, err := configurer.Present(); err != nil || !present {
		t.Fatalf("Present() = %t, %v", present, err)
	}
	// Another program changing the rules, the exit table or the kill switch
	// is seen (exit_rule_tampered), and Replace installs them again.
	for _, tamper := range [][]string{
		{ip, "-4", "rule", "del", "priority", "5405"},
		{ip, "-4", "rule", "add", "priority", "5404", "lookup", "main"},
		{ip, "-4", "route", "add", "198.51.100.0/24", "dev", lan, "table", "5291"},
		{nft, "flush", "chain", "inet", "meshtransit_kill_it", "output"},
	} {
		if output, err := exec.Command(tamper[0], tamper[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v: %s", tamper, err, output)
		}
		if present, err := configurer.Present(); err != nil || present {
			t.Errorf("after %v: Present() = %t, %v", tamper[1:], present, err)
		}
		if err := configurer.Replace(name, true, true); err != nil {
			t.Fatal(err)
		}
		if present, err := configurer.Present(); err != nil || !present {
			rules4, _ := exec.Command(ip, "-4", "rule").CombinedOutput()
			rules6, _ := exec.Command(ip, "-6", "rule").CombinedOutput()
			count, _ := nftRuleCount("meshtransit_kill_it")
			t.Fatalf("after %v reinstalling: Present() = %t, %v\nrules4:\n%s\nrules6:\n%s\ntable:\n%s\nnft %d want %d routes %v",
				tamper[1:], present, err, rules4, rules6, routes(), count, configurer.installed.nftRules, configurer.installed.routes)
		}
	}
	// Without IPv6 at the exit node, IPv6 stops at once; without the LAN,
	// the LAN goes into the mesh.
	if err := configurer.Replace(name, false, false); err != nil {
		t.Fatal(err)
	}
	if table := routes(); strings.Count(table, "default dev "+name) != 1 || strings.Contains(table, "192.168.77.0") {
		t.Errorf("exit table without IPv6 and LAN:\n%s", table)
	}
	if got := routeGet("2001:db8::1", "uid", "0"); !strings.Contains(got, "unreachable") &&
		!strings.Contains(got, "No route") && !strings.Contains(got, "Network is unreachable") {
		t.Errorf("IPv6 without the exit node's IPv6: %s", got)
	}
	// Without the TUN (a helper started before meshd) the kill switch and
	// table still hold: the Internet is unreachable.
	if err := configurer.Replace("", false, false); err != nil {
		t.Fatalf("Replace() without the TUN: %v", err)
	}
	if table := routes(); strings.Contains(table, "default dev "+name) || !strings.Contains(table, "unreachable default") {
		t.Errorf("exit table without the TUN:\n%s", table)
	}
	if err := configurer.Replace(name, false, false); err != nil {
		t.Fatal(err)
	}
	// Once the TUN is gone the table answers unreachable; nothing falls
	// through to the main table.
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	// The kernel took the TUN's route with it: no change by another program.
	if present, err := configurer.Present(); err != nil || !present {
		t.Errorf("Present() once the TUN is gone = %t, %v", present, err)
	}
	rules, err := exec.Command(ip, "-4", "rule", "show", "priority", "5402").CombinedOutput()
	if err != nil || !strings.Contains(string(rules), "from 192.168.77.2 lookup main") ||
		!strings.Contains(string(rules), "from 45.76.10.10 lookup main") {
		t.Errorf("rules for the host's own addresses: %v\n%s", err, rules)
	}
	// Replies from the host's own addresses (SSH, pings) still leave by its
	// own routes, not into the unreachable exit table.
	if got := routeGet("8.8.8.8", "from", "192.168.77.2", "uid", "0"); strings.Contains(got, "unreachable") ||
		strings.Contains(got, "dev "+name) {
		t.Errorf("a reply from the host's own address: %s", got)
	}
	// The host stays reachable from outside: with loose reverse path
	// checks, a marked packet from the LAN is checked against the main
	// table, not the exit table that holds only unreachable now.
	if err := writeSysctl("/proc/sys/net/ipv4/conf/"+lan+"/rp_filter", "2"); err != nil {
		t.Fatal(err)
	}
	if value, _ := readSysctl("/proc/sys/" + validMarkSetting); value != "1" {
		t.Errorf("src_valid_mark = %q while routing through the exit node", value)
	}
	if got := routeGet("192.168.77.2", "from", "192.168.77.50", "iif", lan, "mark", "0x20000000"); !strings.Contains(got, "local 192.168.77.2") {
		t.Errorf("a connection from outside failed the reverse path check: %s", got)
	}
	if got := routeGet("8.8.8.8", "uid", "0"); strings.Contains(got, "dev "+lan) {
		t.Errorf("without the TUN the Internet left by the LAN: %s", got)
	}
	// A helper started after a crash clears what the last one left, the
	// setting it changed included.
	if err := newKernelExitRouteConfigurer(options, meshdUID).Clear(); err != nil {
		t.Fatalf("Clear() error = %v", err)
	}
	if countRules("5402")+countRules("5403")+countRules("5404")+countRules("5405") != 0 || routes() != "\n" {
		t.Errorf("Clear() left rules or routes:\n%s", routes())
	}
	if present, _ := configurer.Present(); present {
		t.Error("Clear() left the kill switch")
	}
	if value, _ := readSysctl("/proc/sys/" + validMarkSetting); value != validMarkBefore {
		t.Errorf("Clear() left src_valid_mark %q, was %q", value, validMarkBefore)
	}
}

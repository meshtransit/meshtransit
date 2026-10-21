//go:build integration && linux

package netadmin

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"meshtransit.net/client/internal/overlayframe"
	"meshtransit.net/client/internal/packetmeta"
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
		}, nil)
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
	checkSelfTest(t, nft, configurer, file, tunLink.Attrs().Index)
	// What a repair must fix is reported: forwarding turned off, a table
	// another tool removed.
	if problems := configurer.Problems(); len(problems) != 0 {
		t.Fatalf("Problems() = %v", problems)
	}
	if err := writeSysctl("/proc/sys/net/ipv4/conf/"+lan+"/forwarding", "0"); err != nil {
		t.Fatal(err)
	}
	if problems := configurer.Problems(); !slices.Equal(problems, []string{ProblemForwardingOff}) {
		t.Fatalf("Problems() with forwarding off = %v", problems)
	}
	if output, err := exec.Command(nft, "delete", "table", "inet", "meshtransit_it").CombinedOutput(); err != nil {
		t.Fatalf("nft delete: %v: %s", err, output)
	}
	if problems := configurer.Problems(); !slices.Equal(problems, []string{ProblemRulesMissing, ProblemForwardingOff}) {
		t.Fatalf("Problems() without the table = %v", problems)
	}
	if count, maximum := configurer.Conntrack(); maximum != 0 && (count < 0 || count > maximum) {
		t.Fatalf("Conntrack() = %d of %d", count, maximum)
	}
	// A setting something reset is set again by the next request.
	if err := writeSysctl("/proc/sys/net/ipv4/conf/"+lan+"/forwarding", "0"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := configurer.ReplaceServed(name, []netip.Prefix{netip.MustParsePrefix("100.127.255.240/32")}, 1280,
		served, nil); err != nil {
		t.Fatal(err)
	}
	if sysctl("net/ipv4/conf/"+lan+"/forwarding") != "1" {
		t.Fatal("reset forwarding was not set again")
	}
	// A route an administrator added for a self-test address is neither
	// replaced nor removed; the self-test reports it instead.
	administrator := &netlink.Route{
		LinkIndex: lanLink(t, lan), Dst: prefixIPNet(netip.PrefixFrom(overlayframe.SelfTestIPv4, 32)),
		Scope: netlink.SCOPE_LINK, Priority: 50,
	}
	if err := netlink.RouteAdd(administrator); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.RouteDel(administrator) })
	if _, _, err := configurer.ReplaceServed(name, []netip.Prefix{netip.MustParsePrefix("100.127.255.240/32")}, 1280,
		served, nil); err != nil {
		t.Fatal(err)
	}
	if problems := configurer.Problems(); !slices.Contains(problems, ProblemSelfTestUnrouted) {
		t.Fatalf("Problems() with an administrator's route = %v", problems)
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
	left, err := selfTestRoutesOf(selfTestRoutes(0)[0])
	if err != nil || len(left) != 1 || left[0].Protocol == selfTestRouteProtocol || left[0].Priority != 50 {
		t.Fatalf("after Clear the self-test address has routes %+v, %v; want only the administrator's", left, err)
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

// checkSelfTest sends self-test packets into the TUN: one the kernel
// forwards towards the Site is counted, one another firewall drops in its
// forward hook, as Docker's policy does, is not.
func checkSelfTest(t *testing.T, nft string, configurer kernelServedConfigurer, tun *os.File, tunIndex int) {
	t.Helper()
	routes, err := netlink.RouteGet(overlayframe.SelfTestIPv4.AsSlice())
	if err != nil || len(routes) == 0 || routes[0].LinkIndex != tunIndex {
		t.Fatalf("the self-test address is not routed into the tun: %+v, %v", routes, err)
	}
	before, known := configurer.SelfTestPackets()
	if !known {
		t.Fatal("the self-test counter cannot be read")
	}
	send := func(sequence uint16) {
		t.Helper()
		packet := packetmeta.EchoRequest(overlayframe.SelfTestIPv4, netip.MustParseAddr("10.200.5.9"), 0x5e1f, sequence)
		if _, err := tun.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	counted := func(want uint64) bool {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for {
			packets, _ := configurer.SelfTestPackets()
			if packets == want || time.Now().After(deadline) {
				return packets == want
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	send(1)
	if !counted(before + 1) {
		t.Fatal("a forwarded self-test packet was not counted")
	}
	for _, command := range [][]string{
		{"add", "table", "ip", "blocker_it"},
		{"add", "chain", "ip", "blocker_it", "forward", "{ type filter hook forward priority -10; policy drop; }"},
	} {
		if output, err := exec.Command(nft, command...).CombinedOutput(); err != nil {
			t.Fatalf("nft %v: %v: %s", command, err, output)
		}
	}
	t.Cleanup(func() { _ = exec.Command(nft, "delete", "table", "ip", "blocker_it").Run() })
	send(2)
	time.Sleep(300 * time.Millisecond)
	if packets, _ := configurer.SelfTestPackets(); packets != before+1 {
		t.Fatalf("a self-test packet another firewall dropped was counted: %d", packets)
	}
	if output, err := exec.Command(nft, "delete", "table", "ip", "blocker_it").CombinedOutput(); err != nil {
		t.Fatalf("nft delete blocker: %v: %s", err, output)
	}
}

func lanLink(t *testing.T, name string) int {
	t.Helper()
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return link.Attrs().Index
}

// TestKernelExitConfigurerIntegration forwards as an exit node on a real
// kernel and reads back the rules: what is not the Internet dropped before
// any accept, SMTP refused, each consumer's connections counted, every
// source translated, forwarding on for the TUN and the default route's
// interface.
func TestKernelExitConfigurerIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}
	nft, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("nft is required to read the rules back")
	}
	const name, uplink = "meshit3", "wanit0"
	file, _, err := (kernelTUNCreator{}).Open(name, 1280, 0,
		[]netip.Prefix{netip.MustParsePrefix("100.127.255.241/32")}, []netip.Prefix{})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })
	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: uplink}}
	if err := netlink.LinkAdd(dummy); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(dummy) })
	address, _ := netlink.ParseAddr("45.76.10.10/29")
	if err := netlink.AddrAdd(dummy, address); err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(dummy); err != nil {
		t.Fatal(err)
	}
	// A default route of its own table metric, so the container's own is kept.
	gateway := netip.MustParseAddr("45.76.10.9")
	route := &netlink.Route{
		LinkIndex: dummy.Attrs().Index, Gw: gateway.AsSlice(), Priority: 4000,
		Dst: prefixIPNet(netip.MustParsePrefix("0.0.0.0/0")),
	}
	if err := netlink.RouteAdd(route); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.RouteDel(route) })
	// A network the host reaches by a route of its own (another VPN) is no
	// Internet for the consumers.
	private := &netlink.Route{
		LinkIndex: dummy.Attrs().Index, Gw: gateway.AsSlice(), Dst: prefixIPNet(netip.MustParsePrefix("52.94.0.0/16")),
	}
	if err := netlink.RouteAdd(private); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.RouteDel(private) })
	// Half the Internet by a route of its own (a VPN client's 128.0.0.0/1)
	// is still the Internet.
	half := &netlink.Route{
		LinkIndex: dummy.Attrs().Index, Gw: gateway.AsSlice(), Dst: prefixIPNet(netip.MustParsePrefix("128.0.0.0/1")),
	}
	if err := netlink.RouteAdd(half); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.RouteDel(half) })
	state := filepath.Join(t.TempDir(), "exit-state.json")
	configurer := kernelServedConfigurer{table: "meshtransit_exit_it", statePath: state, sysctlRoot: "/proc/sys"}
	t.Cleanup(func() { _ = configurer.Clear() })
	public := netip.MustParsePrefix("34.1.2.3/32")
	if _, _, err := configurer.ReplaceServed(name, []netip.Prefix{netip.MustParsePrefix("100.127.255.241/32")}, 1280,
		nil, &exitForwarding{ConntrackPerConsumer: 2048, Excluded: []netip.Prefix{public}}); err != nil {
		t.Fatalf("ReplaceServed(exit) error = %v", err)
	}
	if value, err := readSysctl("/proc/sys/net/ipv4/conf/" + uplink + "/forwarding"); err != nil || value != "1" {
		t.Fatalf("uplink forwarding = %q, %v", value, err)
	}
	listing, err := exec.Command(nft, "list", "table", "inet", "meshtransit_exit_it").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list: %v: %s", err, listing)
	}
	text := string(listing)
	for _, want := range []string{
		"set notinternet4", "set notinternet6", "10.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
		"45.76.10.8/29", "34.1.2.3", "52.94.0.0/16", "4000::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
		"tcp dport 25 drop", "ct count over 2048", "masquerade", "!= @consumers4 drop", "!= @consumers6 drop",
		`iifname "` + name + `" accept`, "udp dport 53 redirect to :1055", "tcp dport 53 redirect to :1055",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("exit table lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "128.0.0.0/1") {
		t.Errorf("half the Internet was taken for no Internet:\n%s", text)
	}
	// What is not the Internet is dropped before the exit's accept.
	if drop, accept := strings.Index(text, "@notinternet4 drop"), strings.Index(text, `iifname "`+name+`" accept`); drop < 0 ||
		accept < 0 || drop > accept {
		t.Errorf("not-Internet drop at %d, accept at %d:\n%s", drop, accept, text)
	}
	t.Log(text)
	// SMTP allowed by both: no port 25 rule.
	if _, _, err := configurer.ReplaceServed(name, []netip.Prefix{netip.MustParsePrefix("100.127.255.241/32")}, 1280,
		nil, &exitForwarding{ConntrackPerConsumer: 2048, SMTP: true}); err != nil {
		t.Fatal(err)
	}
	if listing, err := exec.Command(nft, "list", "table", "inet", "meshtransit_exit_it").CombinedOutput(); err != nil ||
		strings.Contains(string(listing), "dport 25") {
		t.Fatalf("SMTP allowed still drops port 25: %v: %s", err, listing)
	}
	if err := configurer.Clear(); err != nil {
		t.Fatal(err)
	}
	if present, err := configurer.Present(); err != nil || present {
		t.Fatalf("Present() after Clear = %t, %v", present, err)
	}
}

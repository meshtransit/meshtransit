package netadmin

import (
	"net/netip"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"meshtransit.net/client/internal/hostroute"
)

func TestValidPlatformRoutedOptionsDarwin(t *testing.T) {
	t.Parallel()
	if !validRoutedOptions(RoutedOptions{SettingsPath: "/Library/Application Support/MeshTransit/routes.json"}) {
		t.Fatal("settings path alone refused")
	}
	for _, options := range []RoutedOptions{
		{},
		{SettingsPath: "/x", Table: 5267},
		{SettingsPath: "/x", Priority: 5400},
		{SettingsPath: "/x", NftTable: "meshtransit"},
		{SettingsPath: "/x", StatePath: "/run/x"},
	} {
		if validRoutedOptions(options) {
			t.Errorf("validRoutedOptions(%+v) = true", options)
		}
	}
}

func TestLocalRoutesDarwin(t *testing.T) {
	t.Parallel()
	prefix := netip.MustParsePrefix
	table := []hostroute.Route{
		{Prefix: prefix("0.0.0.0/0"), Flags: unix.RTF_GATEWAY, Index: 14, Gateway: &route.Inet4Addr{}},
		{Prefix: prefix("192.168.35.0/24"), Index: 14, Gateway: &route.LinkAddr{Index: 14}},
		{Prefix: prefix("10.0.0.0/8"), Flags: unix.RTF_GATEWAY, Index: 20, Gateway: &route.Inet4Addr{}},
		{Prefix: prefix("192.168.35.7/32"), Flags: unix.RTF_LLINFO | unix.RTF_WASCLONED, Index: 14},
		{Prefix: prefix("100.64.0.0/10"), Index: 30, Gateway: &route.LinkAddr{Index: 30}},
		{Prefix: prefix("10.35.0.0/17"), Flags: hostroute.Mark | unix.RTF_STATIC, Index: 30, Gateway: &route.LinkAddr{Index: 30}},
		{Prefix: prefix("169.254.0.0/16"), Index: 14, Gateway: &route.LinkAddr{Index: 14}},
	}
	local, err := localRoutes(table, 30)
	if err != nil {
		t.Fatalf("localRoutes() error = %v", err)
	}
	want := []localRoute{
		{Prefix: prefix("192.168.35.0/24"), Connected: true},
		{Prefix: prefix("10.0.0.0/8"), Connected: false},
	}
	if len(local) != len(want) || local[0] != want[0] || local[1] != want[1] {
		t.Fatalf("localRoutes() = %+v, want %+v", local, want)
	}
	// The more specific Site route stays: the wider VPN route is no
	// conflict; one inside the attached LAN is.
	kept, refused := withoutLocalConflicts([]netip.Prefix{prefix("10.35.0.0/17"), prefix("192.168.35.128/25")}, local)
	if len(kept) != 1 || kept[0] != prefix("10.35.0.0/17") || len(refused) != 1 {
		t.Fatalf("withoutLocalConflicts() kept %v refused %v", kept, refused)
	}
}

func TestRoutedMessageIsMarked(t *testing.T) {
	t.Parallel()
	message := routedMessage(unix.RTM_ADD, netip.MustParsePrefix("10.35.0.0/17"), &route.LinkAddr{Index: 9}, 0)
	encoded, err := message.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	parsed, err := route.ParseRIB(route.RIBTypeRoute, encoded)
	if err != nil || len(parsed) != 1 {
		t.Fatalf("ParseRIB() = %v, %v", parsed, err)
	}
	table := hostroute.Parse(parsed)
	if len(table) != 1 || table[0].Prefix != netip.MustParsePrefix("10.35.0.0/17") || !table[0].Owned() ||
		table[0].Flags&unix.RTF_HOST != 0 {
		t.Fatalf("round trip = %+v", table)
	}
	pin := routedMessage(unix.RTM_ADD, netip.MustParsePrefix("10.35.0.53/32"), &route.Inet4Addr{IP: [4]byte{192, 168, 35, 1}},
		unix.RTF_GATEWAY)
	if pin.Flags&(unix.RTF_HOST|unix.RTF_GATEWAY|hostroute.Mark) != unix.RTF_HOST|unix.RTF_GATEWAY|hostroute.Mark {
		t.Fatalf("pin flags = %#x", pin.Flags)
	}
}

// A pin through a gateway the host no longer uses is not kept: the next
// request installs it again through the current one.
func TestInstalledRoutedDropsStalePinsFromTheView(t *testing.T) {
	t.Parallel()
	prefix := netip.MustParsePrefix
	gateway := &route.Inet4Addr{IP: [4]byte{192, 168, 35, 1}}
	table := []hostroute.Route{
		{Prefix: prefix("0.0.0.0/0"), Flags: unix.RTF_STATIC | unix.RTF_GATEWAY, Index: 14, Gateway: gateway},
		{
			Prefix: prefix("10.35.0.53/32"), Flags: unix.RTF_STATIC | unix.RTF_GATEWAY | unix.RTF_HOST | hostroute.Mark,
			Index: 14, Gateway: gateway,
		},
		{Prefix: prefix("10.35.0.0/17"), Flags: unix.RTF_STATIC | hostroute.Mark, Index: 30, Gateway: &route.LinkAddr{Index: 30}},
	}
	if !pinCurrent(table, 30, table[1]) {
		t.Fatal("pinCurrent() = false for a pin through the current gateway")
	}
	stale := table[1]
	stale.Gateway = &route.Inet4Addr{IP: [4]byte{172, 20, 10, 1}}
	if pinCurrent(table, 30, stale) {
		t.Fatal("pinCurrent() = true for a pin through an old gateway")
	}
}

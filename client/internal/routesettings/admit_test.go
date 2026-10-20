package routesettings

import (
	"net/netip"
	"testing"
)

// A Site may use unique local space, but never the /48 of an address or
// overlay route the mesh uses on the node, nor fd00::/48 (self-test).
func TestUniqueLocalRoutesStayOffTheMesh(t *testing.T) {
	t.Parallel()
	prefix := netip.MustParsePrefix
	if reason := Usable(prefix("fd12:3456:789a::/48")); reason != "" {
		t.Fatalf("Usable(ULA) = %q", reason)
	}
	for _, reserved := range []string{"fd00::/48", "fd00::/32", "100.64.0.0/16", "198.18.0.0/15"} {
		if reason := Usable(prefix(reserved)); reason != ReasonReserved {
			t.Errorf("Usable(%s) = %q, want %q", reserved, reason, ReasonReserved)
		}
	}
	mesh := []netip.Prefix{prefix("100.64.1.9/32"), prefix("fd07:d4de:9d87:1::9/128"), prefix("fd02:48de:ec1b:1::/64")}
	routes := []netip.Prefix{
		prefix("fd12:3456:789a::/48"), prefix("fd07:d4de:9d87:ff::/64"), prefix("fd02:48de::/32"), prefix("10.35.0.0/17"),
	}
	kept, refused := WithoutMesh(routes, mesh)
	if len(kept) != 2 || kept[0] != routes[0] || kept[1] != routes[3] || len(refused) != 2 ||
		refused[0] != (Refusal{Prefix: routes[1], Reason: ReasonReserved}) ||
		refused[1] != (Refusal{Prefix: routes[2], Reason: ReasonReserved}) {
		t.Fatalf("WithoutMesh() = %v, %v", kept, refused)
	}
}

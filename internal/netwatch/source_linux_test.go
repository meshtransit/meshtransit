//go:build linux

package netwatch

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestIsDefaultRoute(t *testing.T) {
	t.Parallel()

	_, hostNetwork, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatalf("ParseCIDR() error = %v", err)
	}
	_, defaultNetwork, err := net.ParseCIDR("0.0.0.0/0")
	if err != nil {
		t.Fatalf("ParseCIDR() error = %v", err)
	}
	tests := []struct {
		name  string
		route netlink.Route
		want  bool
	}{
		{name: "nil destination", route: netlink.Route{}, want: true},
		{name: "explicit default", route: netlink.Route{Dst: defaultNetwork}, want: true},
		{name: "host network", route: netlink.Route{Dst: hostNetwork}, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if actual := isDefaultRoute(test.route); actual != test.want {
				t.Fatalf("isDefaultRoute() = %t, want %t", actual, test.want)
			}
		})
	}
}

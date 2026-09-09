//go:build integration && linux

package netadmin

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

func TestKernelTUNCreatorIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required")
	}

	const name = "meshit0"
	if _, err := net.InterfaceByName(name); err == nil {
		t.Fatalf("interface %q already exists", name)
	}
	file, err := (kernelTUNCreator{}).Open(
		name,
		1280,
		uint32(os.Geteuid()),
		[]netip.Prefix{netip.MustParsePrefix("100.127.255.253/32")},
		[]netip.Prefix{netip.MustParsePrefix("100.127.255.254/32")},
	)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = file.Close()
		}
	})

	device, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("InterfaceByName() error = %v", err)
	}
	if device.MTU != 1280 || device.Flags&net.FlagUp == 0 {
		t.Fatalf("interface = %#v, want mtu 1280 and up", device)
	}
	link, err := netlink.LinkByName(name)
	if err != nil {
		t.Fatalf("LinkByName() error = %v", err)
	}
	addresses, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil || !hasAddress(addresses, "100.127.255.253/32") {
		t.Fatalf("addresses = %#v, error = %v", addresses, err)
	}
	routes, err := netlink.RouteList(link, netlink.FAMILY_ALL)
	if err != nil || !hasRoute(routes, "100.127.255.254/32") {
		t.Fatalf("routes = %#v, error = %v", routes, err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	closed = true

	deadline := time.Now().Add(time.Second)
	for {
		_, err := net.InterfaceByName(name)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("interface %q still exists after closing its owner", name)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func hasAddress(addresses []netlink.Addr, expected string) bool {
	for _, address := range addresses {
		if address.IPNet != nil && address.IPNet.String() == expected {
			return true
		}
	}

	return false
}

func hasRoute(routes []netlink.Route, expected string) bool {
	for _, route := range routes {
		if route.Dst != nil && route.Dst.String() == expected {
			return true
		}
	}

	return false
}

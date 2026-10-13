//go:build unix

package mobile

import (
	"net/netip"
	"os"
	"syscall"
	"testing"

	"meshtransit.net/client/internal/netadmin"
)

func TestPlatformTUNPassesTheMapsConfiguration(t *testing.T) {
	t.Parallel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	t.Cleanup(func() { _ = reader.Close() })
	// The platform hands over a fresh descriptor; the engine closes it.
	fd, err := syscall.Dup(int(reader.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	tun := &fakeTUN{fd: fd}
	opener := platformTUN{provider: tun, mtu: DefaultMTU}
	config := netadmin.TUNConfig{
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.5/32"), netip.MustParsePrefix("fd07::5/128")},
		Routes:    []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")},
	}
	opened, err := opener.OpenTUN(t.Context(), config)
	if err != nil {
		t.Fatalf("OpenTUN() error = %v", err)
	}
	t.Cleanup(func() { _ = opened.File.Close() })
	if tun.addresses != "100.64.0.5/32,fd07::5/128" || tun.routes != "100.64.0.0/10" || tun.mtu != DefaultMTU {
		t.Fatalf("platform got %q %q %d", tun.addresses, tun.routes, tun.mtu)
	}
	if opened.MTU != DefaultMTU || opened.Name == "" || len(opened.Addresses) != 2 || len(opened.Routes) != 1 ||
		opened.File.Fd() != uintptr(fd) {
		t.Fatalf("OpenTUN() = %+v", opened)
	}
}

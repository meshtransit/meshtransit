//go:build integration && darwin

package netadmin

import (
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestKernelUTUNLifecycle needs root: sudo go test -tags=integration -run
// TestKernelUTUNLifecycle ./client/internal/netadmin/
func TestKernelUTUNLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("creating utun interfaces needs root")
	}
	address4 := netip.MustParsePrefix("100.127.250.1/32")
	address6 := netip.MustParsePrefix("fd07:d4de:9d87:fff::1/128")
	route4 := netip.MustParsePrefix("100.127.250.2/32")
	route6 := netip.MustParsePrefix("fd07:d4de:9d87:fff::2/128")
	creator := kernelTUNCreator{}
	file, name, err := creator.Open("", 1280, 0, []netip.Prefix{address4, address6}, []netip.Prefix{route4, route6})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	link, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("interface %s missing: %v", name, err)
	}
	if link.MTU != 1280 || link.Flags&net.FlagUp == 0 {
		t.Fatalf("interface %s mtu %d flags %v", name, link.MTU, link.Flags)
	}
	addresses, _ := link.Addrs()
	text := ""
	for _, address := range addresses {
		text += address.String() + " "
	}
	if !strings.Contains(text, "100.127.250.1") || !strings.Contains(text, "fd07:d4de:9d87:fff::1") {
		t.Fatalf("interface %s addresses = %s", name, text)
	}
	routeInterface := func(destination string) string {
		output, _ := exec.Command("/sbin/route", "-n", "get", destination).CombinedOutput()
		for _, line := range strings.Split(string(output), "\n") {
			if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "interface:" {
				return fields[1]
			}
		}
		return ""
	}
	if got := routeInterface("100.127.250.2"); got != name {
		t.Fatalf("route to 100.127.250.2 uses %q, want %s", got, name)
	}
	if got := routeInterface("-inet6 fd07:d4de:9d87:fff::2"); got != name && got != "" {
		t.Logf("route -inet6 lookup answered %q", got)
	}
	route5 := netip.MustParsePrefix("100.127.250.5/32")
	if err := creator.ReplaceRoutes(name, []netip.Prefix{route4, route6}, []netip.Prefix{route6, route5}); err != nil {
		t.Fatalf("ReplaceRoutes() error = %v", err)
	}
	if got := routeInterface("100.127.250.5"); got != name {
		t.Fatalf("route to 100.127.250.5 uses %q, want %s", got, name)
	}
	if got := routeInterface("100.127.250.2"); got == name {
		t.Fatal("route to 100.127.250.2 survived its removal")
	}
	_ = file.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := net.InterfaceByName(name); err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("interface %s survived its last descriptor", name)
}

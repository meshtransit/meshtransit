//go:build darwin && !ios

package underlay

import (
	"net/netip"
	"slices"
	"testing"
)

func TestParseScutilResolversKeepsTheNetworksOwn(t *testing.T) {
	output := []byte(`DNS configuration

resolver #1
  nameserver[0] : 192.0.2.53
  port     : 1053
  flags    : Request A records

resolver #2
  domain   : mesh.internal
  nameserver[0] : 10.9.9.9

resolver #3
  domain   : local
  options  : mdns

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : fe80::1%en0
  nameserver[2] : 100.64.0.53
  nameserver[3] : 2001:db8::53
  if_index : 14 (en0)

resolver #2
  nameserver[0] : 10.1.1.1
  if_index : 21 (utun4)

resolver #3
  nameserver[0] : 192.168.1.1
  if_index : 15 (en1)
`)
	got := parseScutilResolvers(output)
	want := []netip.AddrPort{
		netip.MustParseAddrPort("192.168.1.1:53"), netip.MustParseAddrPort("[2001:db8::53]:53"),
	}
	if !slices.Equal(got, want) {
		t.Fatalf("parseScutilResolvers() = %v, want %v", got, want)
	}
}

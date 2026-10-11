package netadmin

import (
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

func TestDarwinKernelStructSizes(t *testing.T) {
	t.Parallel()
	// Sizes from <net/if.h> and <netinet6/in6_var.h>; the ioctl numbers
	// encode them, so a mismatch makes the kernel refuse the request.
	for name, test := range map[string]struct{ got, want uintptr }{
		"ifreq":        {unsafe.Sizeof(ifreqFlags{}), 32},
		"ifaliasreq":   {unsafe.Sizeof(ifAliasReq{}), 64},
		"in6_aliasreq": {unsafe.Sizeof(in6AliasReq{}), 128},
		"ifreq addr":   {unsafe.Sizeof(ifreqAddr4{}), 32},
	} {
		if test.got != test.want {
			t.Errorf("sizeof(%s) = %d, want %d", name, test.got, test.want)
		}
	}
	if siocAIFAddrIn6>>16&0x1fff != uint(unsafe.Sizeof(in6AliasReq{})) {
		t.Errorf("SIOCAIFADDR_IN6 length field disagrees with in6_aliasreq")
	}
}

func TestHostRouteMessage(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		prefix netip.Prefix
		add    bool
	}{
		{netip.MustParsePrefix("100.64.0.4/32"), true},
		{netip.MustParsePrefix("fd07:d4de:9d87::4/128"), false},
	} {
		encoded, err := hostRouteMessage(17, test.prefix, test.add, 4242)
		if err != nil {
			t.Fatalf("hostRouteMessage(%s) error = %v", test.prefix, err)
		}
		messages, err := route.ParseRIB(route.RIBTypeRoute, encoded)
		if err != nil || len(messages) != 1 {
			t.Fatalf("ParseRIB(%s) = %d messages, %v", test.prefix, len(messages), err)
		}
		message, ok := messages[0].(*route.RouteMessage)
		if !ok {
			t.Fatalf("message %T", messages[0])
		}
		wantType := unix.RTM_DELETE
		if test.add {
			wantType = unix.RTM_ADD
		}
		if message.Type != wantType || message.Flags&(unix.RTF_HOST|unix.RTF_STATIC|unix.RTF_UP) !=
			unix.RTF_HOST|unix.RTF_STATIC|unix.RTF_UP {
			t.Fatalf("message type %d flags %#x", message.Type, message.Flags)
		}
		gateway, ok := message.Addrs[unix.RTAX_GATEWAY].(*route.LinkAddr)
		if !ok || gateway.Index != 17 {
			t.Fatalf("gateway = %#v, want link index 17", message.Addrs[unix.RTAX_GATEWAY])
		}
		var destination netip.Addr
		switch address := message.Addrs[unix.RTAX_DST].(type) {
		case *route.Inet4Addr:
			destination = netip.AddrFrom4(address.IP)
		case *route.Inet6Addr:
			destination = netip.AddrFrom16(address.IP)
		}
		if destination != test.prefix.Addr() {
			t.Fatalf("destination = %s, want %s", destination, test.prefix.Addr())
		}
	}
	if _, err := hostRouteMessage(1, netip.MustParsePrefix("100.64.0.0/24"), true, 1); err == nil {
		t.Fatal("hostRouteMessage accepted a subnet route")
	}
}

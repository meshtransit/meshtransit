//go:build linux

package netadmin

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestConfigureLinkUsesNetlink(t *testing.T) {
	t.Parallel()

	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "meshdns0"}}
	configurer := &fakeLinkConfigurer{link: link}

	if err := configureLinkWith(configurer, "meshdns0", 1280); err != nil {
		t.Fatalf("configureLinkWith() error = %v", err)
	}
	if configurer.requestedName != "meshdns0" {
		t.Fatalf("requested link = %q, want meshdns0", configurer.requestedName)
	}
	if configurer.mtuLink != link || configurer.mtu != 1280 {
		t.Fatalf("MTU configuration = (%T, %d), want (%T, 1280)", configurer.mtuLink, configurer.mtu, link)
	}
	if configurer.upLink != link {
		t.Fatalf("link brought up = %T, want %T", configurer.upLink, link)
	}
}

func TestReplaceRoutesAddsBeforeRemoving(t *testing.T) {
	t.Parallel()

	current := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.2/32"),
		netip.MustParsePrefix("100.64.0.3/32"),
	}
	desired := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.3/32"),
		netip.MustParsePrefix("100.64.0.4/32"),
	}
	configurer := &fakeRouteConfigurer{
		link: &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Index: 7, Name: "mesh0"}},
	}
	if err := replaceRoutesWith(configurer, "mesh0", current, desired); err != nil {
		t.Fatalf("replaceRoutesWith() error = %v", err)
	}
	want := []routeOperation{
		{prefix: desired[1], added: true},
		{prefix: current[0]},
	}
	if len(configurer.operations) != len(want) {
		t.Fatalf("operations = %#v, want %#v", configurer.operations, want)
	}
	for index := range want {
		if configurer.operations[index] != want[index] {
			t.Fatalf("operations = %#v, want %#v", configurer.operations, want)
		}
	}
}

func TestReplaceRoutesRollsBackCompletedChanges(t *testing.T) {
	t.Parallel()

	current := []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")}
	desired := []netip.Prefix{netip.MustParsePrefix("100.64.0.4/32")}
	configurer := &fakeRouteConfigurer{
		link:   &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Index: 7, Name: "mesh0"}},
		failAt: 2,
	}
	err := replaceRoutesWith(configurer, "mesh0", current, desired)
	if err == nil {
		t.Fatal("replaceRoutesWith() error = nil")
	}
	if strings.Contains(err.Error(), "100.64.") {
		t.Fatalf("replaceRoutesWith() disclosed an overlay route: %v", err)
	}
	want := []routeOperation{
		{prefix: desired[0], added: true},
		{prefix: current[0]},
		{prefix: desired[0]},
	}
	if len(configurer.operations) != len(want) {
		t.Fatalf("operations = %#v, want %#v", configurer.operations, want)
	}
	for index := range want {
		if configurer.operations[index] != want[index] {
			t.Fatalf("operations = %#v, want %#v", configurer.operations, want)
		}
	}
}

func TestConfigureLinkFailsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		mtu        int
		configurer *fakeLinkConfigurer
	}{
		{
			name: "invalid mtu",
			mtu:  -1,
			configurer: &fakeLinkConfigurer{
				link: &netlink.Dummy{},
			},
		},
		{
			name: "link lookup",
			mtu:  1280,
			configurer: &fakeLinkConfigurer{
				linkErr: errors.New("lookup failed"),
			},
		},
		{
			name: "mtu update",
			mtu:  1280,
			configurer: &fakeLinkConfigurer{
				link:   &netlink.Dummy{},
				mtuErr: errors.New("mtu failed"),
			},
		},
		{
			name: "link activation",
			mtu:  1280,
			configurer: &fakeLinkConfigurer{
				link:  &netlink.Dummy{},
				upErr: errors.New("up failed"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := configureLinkWith(test.configurer, "meshdns0", test.mtu); err == nil {
				t.Fatal("configureLinkWith() error = nil")
			}
		})
	}
}

type fakeLinkConfigurer struct {
	link          netlink.Link
	linkErr       error
	mtuErr        error
	upErr         error
	requestedName string
	mtuLink       netlink.Link
	mtu           int
	upLink        netlink.Link
}

type routeOperation struct {
	prefix netip.Prefix
	added  bool
}

type fakeRouteConfigurer struct {
	link       netlink.Link
	failAt     int
	operations []routeOperation
}

func (f *fakeRouteConfigurer) LinkByName(string) (netlink.Link, error) {
	return f.link, nil
}

func (f *fakeRouteConfigurer) Add(route *netlink.Route) error {
	return f.record(route, true)
}

func (f *fakeRouteConfigurer) Delete(route *netlink.Route) error {
	return f.record(route, false)
}

func (f *fakeRouteConfigurer) record(route *netlink.Route, added bool) error {
	prefix, ok := netip.AddrFromSlice(route.Dst.IP)
	if !ok {
		return errors.New("invalid route")
	}
	ones, _ := route.Dst.Mask.Size()
	f.operations = append(f.operations, routeOperation{
		prefix: netip.PrefixFrom(prefix.Unmap(), ones),
		added:  added,
	})
	if f.failAt > 0 && len(f.operations) == f.failAt {
		return errors.New("injected route failure")
	}

	return nil
}

func (f *fakeLinkConfigurer) LinkByName(name string) (netlink.Link, error) {
	f.requestedName = name

	return f.link, f.linkErr
}

func (f *fakeLinkConfigurer) SetMTU(link netlink.Link, mtu int) error {
	f.mtuLink = link
	f.mtu = mtu

	return f.mtuErr
}

func (f *fakeLinkConfigurer) SetUp(link netlink.Link) error {
	f.upLink = link

	return f.upErr
}

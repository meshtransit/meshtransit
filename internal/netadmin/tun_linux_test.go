//go:build linux

package netadmin

import (
	"errors"
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

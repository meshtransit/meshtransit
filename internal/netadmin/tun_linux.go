//go:build linux

package netadmin

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const tunDevicePath = "/dev/net/tun"

type kernelTUNCreator struct{}

type linkConfigurer interface {
	LinkByName(string) (netlink.Link, error)
	SetMTU(netlink.Link, int) error
	SetUp(netlink.Link) error
}

type kernelLinkConfigurer struct{}

func (kernelLinkConfigurer) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}

func (kernelLinkConfigurer) SetMTU(link netlink.Link, mtu int) error {
	return netlink.LinkSetMTU(link, mtu)
}

func (kernelLinkConfigurer) SetUp(link netlink.Link) error {
	return netlink.LinkSetUp(link)
}

func (kernelTUNCreator) Open(
	name string,
	mtu int,
	ownerUID uint32,
	addresses []netip.Prefix,
	routes []netip.Prefix,
) (*os.File, error) {
	descriptor, err := unix.Open(
		tunDevicePath,
		unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("opening tun device: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), "meshnetd-tun")
	if file == nil {
		_ = unix.Close(descriptor)

		return nil, errors.New("creating tun file: invalid descriptor")
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = file.Close()
		}
	}()

	request, err := unix.NewIfreq(name)
	if err != nil {
		return nil, fmt.Errorf("creating tun interface request: %w", err)
	}
	request.SetUint16(uint16(unix.IFF_TUN | unix.IFF_NO_PI))
	if err := unix.IoctlIfreq(descriptor, unix.TUNSETIFF, request); err != nil {
		return nil, fmt.Errorf("creating tun interface: %w", err)
	}
	if _, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(descriptor),
		uintptr(unix.TUNSETOWNER),
		uintptr(ownerUID),
	); errno != 0 {
		return nil, fmt.Errorf("setting tun owner: %w", errno)
	}
	if err := configureLink(request.Name(), mtu); err != nil {
		return nil, err
	}
	if err := configureAddressesAndRoutes(request.Name(), addresses, routes); err != nil {
		return nil, err
	}

	succeeded = true

	return file, nil
}

func configureAddressesAndRoutes(
	name string,
	addresses []netip.Prefix,
	routes []netip.Prefix,
) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("finding tun link: %w", err)
	}
	for _, prefix := range addresses {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: prefixIPNet(prefix)}); err != nil {
			return fmt.Errorf("adding tun address: %w", err)
		}
	}
	for _, prefix := range routes {
		route := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       prefixIPNet(prefix),
			Scope:     netlink.SCOPE_LINK,
		}
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("adding tun route: %w", err)
		}
	}

	return nil
}

func prefixIPNet(prefix netip.Prefix) *net.IPNet {
	address := prefix.Addr()
	return &net.IPNet{
		IP:   net.IP(address.AsSlice()),
		Mask: net.CIDRMask(prefix.Bits(), address.BitLen()),
	}
}

func configureLink(name string, mtu int) error {
	return configureLinkWith(kernelLinkConfigurer{}, name, mtu)
}

func configureLinkWith(configurer linkConfigurer, name string, mtu int) error {
	if mtu < 0 || uint64(mtu) > uint64(^uint32(0)) {
		return errors.New("tun mtu is outside uint32")
	}
	link, err := configurer.LinkByName(name)
	if err != nil {
		return fmt.Errorf("finding tun link for configuration: %w", err)
	}
	if err := configurer.SetMTU(link, mtu); err != nil {
		return fmt.Errorf("setting tun mtu: %w", err)
	}
	if err := configurer.SetUp(link); err != nil {
		return fmt.Errorf("bringing tun interface up: %w", err)
	}

	return nil
}

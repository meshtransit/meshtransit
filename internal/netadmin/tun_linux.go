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
	if mtu < 0 || uint64(mtu) > uint64(^uint32(0)) {
		return errors.New("tun mtu is outside uint32")
	}
	descriptor, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("opening interface control socket: %w", err)
	}
	defer func() { _ = unix.Close(descriptor) }()

	mtuRequest, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("creating mtu request: %w", err)
	}
	mtuRequest.SetUint32(uint32(mtu))
	if err := unix.IoctlIfreq(descriptor, unix.SIOCSIFMTU, mtuRequest); err != nil {
		return fmt.Errorf("setting tun mtu: %w", err)
	}

	flagsRequest, err := unix.NewIfreq(name)
	if err != nil {
		return fmt.Errorf("creating link request: %w", err)
	}
	if err := unix.IoctlIfreq(descriptor, unix.SIOCGIFFLAGS, flagsRequest); err != nil {
		return fmt.Errorf("reading tun flags: %w", err)
	}
	flagsRequest.SetUint16(flagsRequest.Uint16() | uint16(unix.IFF_UP))
	if err := unix.IoctlIfreq(descriptor, unix.SIOCSIFFLAGS, flagsRequest); err != nil {
		return fmt.Errorf("bringing tun interface up: %w", err)
	}

	return nil
}

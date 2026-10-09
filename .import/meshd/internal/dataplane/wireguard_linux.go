//go:build linux

package dataplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"

	relaywire "github.com/meshtransit/meshd/internal/compat/derp"
	"github.com/meshtransit/meshd/internal/pathdiscovery"
	"github.com/meshtransit/meshd/internal/relay"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type officialWireGuardFactory struct {
	generations *socketGenerationSource
}

type officialWireGuardDevice struct {
	device    *device.Device
	discovery *pathdiscovery.Discovery
	bind      *sharedBind
	datagrams *controlDatagramMux
}

func newWireGuardFactory() (wireGuardFactory, error) {
	return &officialWireGuardFactory{generations: &socketGenerationSource{}}, nil
}

func (f *officialWireGuardFactory) New(
	ctx context.Context,
	file *os.File,
	mtu int,
	filter *policyFilter,
	observer PacketObserver,
	relayConfig *relay.Config,
) (wireGuardDevice, error) {
	if f == nil || f.generations == nil {
		return nil, errors.New("dataplane: wireguard factory is not initialized")
	}
	tunDevice, err := adoptPrivilegedTUNDescriptor(
		file,
		mtu,
		tun.CreateUnmonitoredTUNFromFD,
	)
	if err != nil {
		return nil, err
	}
	if filter != nil || observer != nil {
		tunDevice = &observedTUN{
			Device:   tunDevice,
			filter:   filter,
			observer: observer,
		}
	}
	logger := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf:   device.DiscardLogf,
	}
	var relayPool *relay.Pool
	if relayConfig != nil {
		relayPool, err = relay.New(ctx, *relayConfig, relaywire.NewDialer())
		if err != nil {
			_ = tunDevice.Close()

			return nil, err
		}
	}
	bind, err := newSharedBindWithRelay(
		conn.NewDefaultBind(),
		f.generations,
		relayPool,
	)
	if err != nil {
		_ = tunDevice.Close()
		_ = relayPool.Close()

		return nil, err
	}
	discovery, err := pathdiscovery.NewDiscovery(bind)
	if err != nil {
		_ = tunDevice.Close()
		_ = relayPool.Close()

		return nil, err
	}
	datagrams, err := newControlDatagramMux(discovery)
	if err != nil {
		_ = tunDevice.Close()
		_ = relayPool.Close()

		return nil, err
	}
	if err := bind.setDatagramHandler(datagrams); err != nil {
		_ = tunDevice.Close()
		_ = relayPool.Close()

		return nil, err
	}

	return &officialWireGuardDevice{
		device:    newEndpointAuthorityDevice(tunDevice, bind, logger),
		discovery: discovery,
		bind:      bind,
		datagrams: datagrams,
	}, nil
}

type inheritedTUNOpener func(int) (tun.Device, string, error)

// adoptPrivilegedTUNDescriptor transfers a helper-configured TUN descriptor
// into the unprivileged packet engine without attempting privileged link
// changes. The duplicate gives the WireGuard adapter sole descriptor ownership.
func adoptPrivilegedTUNDescriptor(
	file *os.File,
	expectedMTU int,
	open inheritedTUNOpener,
) (tun.Device, error) {
	if file == nil || expectedMTU < 1280 || expectedMTU > 9000 {
		return nil, errors.New("dataplane: inherited tun metadata is invalid")
	}
	if open == nil {
		return nil, errors.New("dataplane: inherited tun opener is required")
	}

	descriptor, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("dataplane: duplicating inherited tun descriptor: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = unix.Close(descriptor)

		return nil, fmt.Errorf("dataplane: transferring inherited tun descriptor: %w", err)
	}

	tunDevice, actualName, err := open(descriptor)
	if err != nil {
		if tunDevice != nil {
			_ = tunDevice.Close()
		} else {
			_ = unix.Close(descriptor)
		}

		return nil, fmt.Errorf("dataplane: opening inherited tun descriptor: %w", err)
	}
	if tunDevice == nil {
		_ = unix.Close(descriptor)

		return nil, errors.New("dataplane: inherited tun opener returned no device")
	}
	if actualName == "" {
		_ = tunDevice.Close()

		return nil, errors.New("dataplane: inherited tun name is empty")
	}
	actualMTU, err := tunDevice.MTU()
	if err != nil {
		_ = tunDevice.Close()

		return nil, fmt.Errorf("dataplane: reading inherited tun mtu: %w", err)
	}
	if actualMTU != expectedMTU {
		_ = tunDevice.Close()

		return nil, errors.New("dataplane: inherited tun mtu does not match helper response")
	}

	return tunDevice, nil
}

func (d *officialWireGuardDevice) Configure(configuration io.Reader) error {
	return configureWithEndpointAuthority(d.device, configuration)
}

func (d *officialWireGuardDevice) Up() error { return d.device.Up() }

func (d *officialWireGuardDevice) Close() {
	d.device.Close()
	_ = d.bind.closeRelayPermanently()
}

func (d *officialWireGuardDevice) DiscoverySocket() pathdiscovery.Socket {
	if d == nil || d.discovery == nil {
		return pathdiscovery.Socket{}
	}

	return d.discovery.Socket()
}

func (d *officialWireGuardDevice) DiscoverEndpoints(
	ctx context.Context,
	scope uint64,
	servers []netip.AddrPort,
) (pathdiscovery.DiscoveryResult, error) {
	if d == nil || d.discovery == nil {
		return pathdiscovery.DiscoveryResult{}, pathdiscovery.ErrTransportClosed
	}

	return d.discovery.Discover(ctx, scope, servers)
}

func (d *officialWireGuardDevice) Socket() pathdiscovery.Socket {
	if d == nil || d.bind == nil {
		return pathdiscovery.Socket{}
	}

	return d.bind.Socket()
}

func (d *officialWireGuardDevice) SendDatagram(
	packet []byte,
	destination netip.AddrPort,
) (pathdiscovery.Socket, error) {
	if d == nil || d.bind == nil {
		return pathdiscovery.Socket{}, pathdiscovery.ErrTransportClosed
	}

	return d.bind.SendDatagram(packet, destination)
}

func (d *officialWireGuardDevice) SetPeerProbeHandler(
	handler pathdiscovery.DatagramHandler,
) {
	if d == nil || d.datagrams == nil {
		return
	}
	d.datagrams.setPeerHandler(handler)
}

func (d *officialWireGuardDevice) RelayHealth() relay.HealthSnapshot {
	if d == nil || d.bind == nil {
		return relay.HealthSnapshot{}
	}

	return d.bind.RelayHealth()
}

func (d *officialWireGuardDevice) PrepareRelayRegion(regionID int) error {
	if d == nil || d.bind == nil {
		return pathdiscovery.ErrTransportClosed
	}

	return d.bind.PrepareRelayRegion(regionID)
}

func (d *officialWireGuardDevice) ReplaceRelayPeers(peers []relay.Peer) error {
	if d == nil || d.bind == nil {
		return pathdiscovery.ErrTransportClosed
	}

	return d.bind.ReplaceRelayPeers(peers)
}

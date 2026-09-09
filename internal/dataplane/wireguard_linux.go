//go:build linux

package dataplane

import (
	"context"
	"io"
	"net/netip"
	"os"

	"github.com/meshtransit/meshd/internal/pathdiscovery"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type officialWireGuardFactory struct{}

type officialWireGuardDevice struct {
	device    *device.Device
	discovery *pathdiscovery.Discovery
	bind      *sharedBind
	datagrams *controlDatagramMux
}

func newWireGuardFactory() (wireGuardFactory, error) {
	return officialWireGuardFactory{}, nil
}

func (officialWireGuardFactory) New(
	file *os.File,
	mtu int,
	filter *policyFilter,
	observer PacketObserver,
) (wireGuardDevice, error) {
	tunDevice, err := tun.CreateTUNFromFile(file, mtu)
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
	bind, err := newSharedBind(conn.NewDefaultBind())
	if err != nil {
		_ = tunDevice.Close()

		return nil, err
	}
	discovery, err := pathdiscovery.NewDiscovery(bind)
	if err != nil {
		_ = tunDevice.Close()

		return nil, err
	}
	datagrams, err := newControlDatagramMux(discovery)
	if err != nil {
		_ = tunDevice.Close()

		return nil, err
	}
	if err := bind.setDatagramHandler(datagrams); err != nil {
		_ = tunDevice.Close()

		return nil, err
	}

	return &officialWireGuardDevice{
		device:    device.NewDevice(tunDevice, bind, logger),
		discovery: discovery,
		bind:      bind,
		datagrams: datagrams,
	}, nil
}

func (d *officialWireGuardDevice) Configure(configuration io.Reader) error {
	return d.device.IpcSetOperation(configuration)
}

func (d *officialWireGuardDevice) Up() error { return d.device.Up() }

func (d *officialWireGuardDevice) Close() { d.device.Close() }

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

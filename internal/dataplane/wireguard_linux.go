//go:build linux

package dataplane

import (
	"io"
	"os"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type officialWireGuardFactory struct{}

type officialWireGuardDevice struct {
	device *device.Device
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
		return nil, err
	}

	return &officialWireGuardDevice{
		device: device.NewDevice(tunDevice, bind, logger),
	}, nil
}

func (d *officialWireGuardDevice) Configure(configuration io.Reader) error {
	return d.device.IpcSetOperation(configuration)
}

func (d *officialWireGuardDevice) Up() error { return d.device.Up() }

func (d *officialWireGuardDevice) Close() { d.device.Close() }

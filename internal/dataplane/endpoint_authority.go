package dataplane

import (
	"io"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// meshd owns peer endpoint selection: the path selector writes a peer's
// endpoint only after authenticated proof, and proof expiry restores the
// signed base endpoint. WireGuard's protocol-level roaming would instead adopt
// the source of every authenticated packet. A relayed packet still in flight
// after a direct promotion then silently moves sends back to the relay while
// the selector still records a direct path, and with relay latency above the
// reassert period the peer never heals. Pinning makes every configured
// endpoint authoritative; only a peer without one learns from packets.

// newEndpointAuthorityDevice creates a WireGuard device whose peers created
// with an endpoint never roam.
func newEndpointAuthorityDevice(tunDevice tun.Device, bind conn.Bind, logger *device.Logger) *device.Device {
	created := device.NewDevice(tunDevice, bind, logger)
	created.DisableSomeRoamingForBrokenMobileSemantics()

	return created
}

// configureWithEndpointAuthority applies one UAPI configuration and then pins
// every peer that now has an endpoint, including peers whose endpoint was set
// by an update_only write after creation. Pinning a peer that learned its
// endpoint from a packet keeps that path until meshd configures another.
func configureWithEndpointAuthority(target *device.Device, configuration io.Reader) error {
	if err := target.IpcSetOperation(configuration); err != nil {
		return err
	}
	target.DisableSomeRoamingForBrokenMobileSemantics()

	return nil
}

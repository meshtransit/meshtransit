package dataplane

import (
	"errors"
	"fmt"

	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/netadmin"
)

// inProcessTUN takes a TUN device opened in this process (Windows' Wintun
// adapter, a mobile platform's VPN interface) after checking its MTU.
func inProcessTUN(tunValue netadmin.TUN) (tun.Device, error) {
	if tunValue.Device == nil || tunValue.File != nil {
		return nil, errors.New("dataplane: an in-process tun needs a device and no descriptor")
	}
	actualMTU, err := tunValue.Device.MTU()
	if err != nil {
		return nil, fmt.Errorf("dataplane: reading the tun mtu: %w", err)
	}
	if actualMTU != tunValue.MTU {
		return nil, fmt.Errorf("dataplane: tun mtu %d differs from %d", actualMTU, tunValue.MTU)
	}

	return tunValue.Device, nil
}

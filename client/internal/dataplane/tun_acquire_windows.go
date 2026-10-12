//go:build windows

package dataplane

import (
	"errors"
	"fmt"
	"log/slog"

	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/netadmin"
)

// acquireTUN takes the Wintun device the service opened in this process.
func acquireTUN(tunValue netadmin.TUN, _ *slog.Logger) (tun.Device, error) {
	if tunValue.Device == nil || tunValue.File != nil {
		return nil, errors.New("dataplane: the Windows tun must be an in-process device")
	}
	actualMTU, err := tunValue.Device.MTU()
	if err != nil {
		return nil, fmt.Errorf("dataplane: reading the adapter mtu: %w", err)
	}
	if actualMTU != tunValue.MTU {
		return nil, fmt.Errorf("dataplane: adapter mtu %d differs from %d", actualMTU, tunValue.MTU)
	}

	return tunValue.Device, nil
}

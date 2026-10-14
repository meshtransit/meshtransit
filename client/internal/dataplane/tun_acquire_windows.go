//go:build windows

package dataplane

import (
	"errors"
	"log/slog"
	"os"

	"golang.zx2c4.com/wireguard/tun"

	"meshtransit.net/client/internal/netadmin"
)

// acquireTUN takes the Wintun device the service opened in this process.
func acquireTUN(tunValue netadmin.TUN, _ *slog.Logger) (tun.Device, error) {
	if tunValue.Device == nil {
		return nil, errors.New("dataplane: the Windows tun must be an in-process device")
	}

	return inProcessTUN(tunValue)
}

// AdoptTUN is the mobile platforms' descriptor path (client/mobile); Windows
// TUNs are Wintun devices opened in process, so it always fails. It takes
// file, as on other systems.
func AdoptTUN(file *os.File, _ int, _ *slog.Logger) (tun.Device, error) {
	if file != nil {
		_ = file.Close()
	}

	return nil, errors.New("dataplane: descriptor TUNs are unsupported on Windows")
}

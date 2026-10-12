//go:build windows

package localapi

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

// dialer connects to meshd's named pipe and requires SYSTEM, which runs the
// service, to own it, so meshctl never talks to an impostor pipe.
func dialer(socketPath string, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
		if err != nil {
			return nil, fmt.Errorf("localapi: building the SYSTEM SID: %w", err)
		}
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		return (&namedpipe.DialConfig{ExpectedOwner: system}).DialContext(dialCtx, socketPath)
	}
}

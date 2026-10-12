//go:build !windows

package localapi

import (
	"context"
	"net"
	"time"
)

// dialer connects to meshd's Unix socket.
func dialer(socketPath string, timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}

	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", socketPath)
	}
}

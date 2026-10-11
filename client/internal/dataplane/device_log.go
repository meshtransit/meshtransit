//go:build linux || darwin

package dataplane

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

// deviceLogInterval bounds how often one kind of WireGuard message is logged:
// a send error repeats for every packet while the network is down.
const deviceLogInterval = 30 * time.Second

// deviceLogAddress matches IPv4 and IPv6 addresses, which the log must not
// carry (path logs use endpoint digests for the same reason).
var deviceLogAddress = regexp.MustCompile(
	`\[[0-9A-Fa-f:.%]+\]|\b\d{1,3}(?:\.\d{1,3}){3}\b|\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{0,4}){2,7}\b`,
)

// deviceLogLimiter forwards WireGuard's errors, and the verbose receive
// failures that stop a receive routine, to slog at most once per interval
// per message format.
type deviceLogLimiter struct {
	logger     *slog.Logger
	now        func() time.Time
	mu         sync.Mutex
	last       map[string]time.Time
	suppressed map[string]int
}

func newDeviceLogger(logger *slog.Logger, now func() time.Time) *device.Logger {
	if logger == nil {
		return &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	}
	limiter := &deviceLogLimiter{
		logger:     logger,
		now:        now,
		last:       make(map[string]time.Time),
		suppressed: make(map[string]int),
	}

	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			if strings.HasPrefix(format, "Failed to receive") {
				limiter.log(slog.LevelInfo, format, args)
			}
		},
		Errorf: func(format string, args ...any) {
			limiter.log(slog.LevelWarn, format, args)
		},
	}
}

func (l *deviceLogLimiter) log(level slog.Level, format string, args []any) {
	now := l.now()
	l.mu.Lock()
	if last, seen := l.last[format]; seen && now.Sub(last) < deviceLogInterval {
		l.suppressed[format]++
		l.mu.Unlock()

		return
	}
	suppressed := l.suppressed[format]
	delete(l.suppressed, format)
	l.last[format] = now
	l.mu.Unlock()

	message := deviceLogAddress.ReplaceAllString(fmt.Sprintf(format, args...), "<addr>")
	attributes := []any{"detail", message}
	if suppressed > 0 {
		attributes = append(attributes, "suppressed", suppressed)
	}
	l.logger.Log(context.Background(), level, "wireguard device message", attributes...)
}

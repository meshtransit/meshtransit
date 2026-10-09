// Package servicemanager reports daemon lifecycle state to the host service manager.
package servicemanager

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	notifySocketEnvironment = "NOTIFY_SOCKET"
	maxNotifySocketBytes    = 107
	notifyTimeout           = time.Second
)

// Notifier reports lifecycle state through systemd's stable notification
// socket protocol. A disabled notifier is a no-op for non-systemd launches.
type Notifier struct {
	address string
}

// New reads and removes NOTIFY_SOCKET from the process environment. Removing
// the variable prevents child processes from impersonating the daemon.
func New() (*Notifier, error) {
	address, present := os.LookupEnv(notifySocketEnvironment)
	if err := os.Unsetenv(notifySocketEnvironment); err != nil {
		return nil, fmt.Errorf("remove service-manager environment: %w", err)
	}
	if !present || address == "" {
		return &Notifier{}, nil
	}
	if err := validateAddress(address); err != nil {
		return nil, err
	}

	return &Notifier{address: address}, nil
}

// Ready reports that startup has completed and the daemon's local socket is
// accepting queued connections.
func (n *Notifier) Ready(ctx context.Context) error {
	return n.send(ctx, "READY=1")
}

// Stopping reports that an orderly shutdown has begun.
func (n *Notifier) Stopping(ctx context.Context) error {
	return n.send(ctx, "STOPPING=1")
}

func (n *Notifier) send(ctx context.Context, state string) error {
	if n == nil {
		return errors.New("service-manager notifier is nil")
	}
	if n.address == "" {
		return nil
	}
	if ctx == nil {
		return errors.New("service-manager notification context is nil")
	}

	notifyContext, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()

	address := n.address
	if address[0] == '@' {
		address = "\x00" + address[1:]
	}
	connection, err := (&net.Dialer{}).DialContext(notifyContext, "unixgram", address)
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer func() { _ = connection.Close() }()

	deadline, ok := notifyContext.Deadline()
	if ok {
		if err := connection.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("set service-manager write deadline: %w", err)
		}
	}
	written, err := connection.Write([]byte(state))
	if err != nil {
		return fmt.Errorf("send service-manager state: %w", err)
	}
	if written != len(state) {
		return fmt.Errorf("send service-manager state: short write: %d of %d bytes", written, len(state))
	}

	return nil
}

func validateAddress(address string) error {
	if strings.IndexByte(address, 0) >= 0 {
		return errors.New("NOTIFY_SOCKET contains a NUL byte")
	}
	if len(address) > maxNotifySocketBytes {
		return fmt.Errorf("NOTIFY_SOCKET exceeds %d bytes", maxNotifySocketBytes)
	}
	if address[0] == '@' {
		if len(address) == 1 {
			return errors.New("NOTIFY_SOCKET abstract name is empty")
		}

		return nil
	}
	if address[0] != '/' {
		return errors.New("NOTIFY_SOCKET must be an absolute or abstract Unix socket")
	}

	return nil
}

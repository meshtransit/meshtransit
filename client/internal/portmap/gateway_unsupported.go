//go:build !linux && !darwin && !windows

package portmap

// DefaultGateway is implemented on Linux, macOS and Windows only.
func DefaultGateway() (Gateway, error) {
	return Gateway{}, ErrNoGateway
}

//go:build !linux

package portmap

// DefaultGateway is implemented on Linux only.
func DefaultGateway() (Gateway, error) {
	return Gateway{}, ErrNoGateway
}

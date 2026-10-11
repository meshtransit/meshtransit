//go:build !linux && !darwin

package portmap

// DefaultGateway is implemented on Linux and macOS only.
func DefaultGateway() (Gateway, error) {
	return Gateway{}, ErrNoGateway
}

//go:build windows

package portmap

import (
	"errors"
	"testing"
)

func TestDefaultGatewayOnHost(t *testing.T) {
	t.Parallel()
	gateway, err := DefaultGateway()
	if errors.Is(err, ErrNoGateway) {
		t.Skip("host has no IPv4 default gateway")
	}
	if err != nil {
		t.Fatalf("DefaultGateway() error = %v", err)
	}
	if !gateway.Valid() {
		t.Fatalf("DefaultGateway() = %+v, not valid", gateway)
	}
	t.Logf("gateway %s via local %s", gateway.Addr, gateway.Local)
}

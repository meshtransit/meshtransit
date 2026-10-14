//go:build darwin || windows

package portmap

import (
	"net/netip"
	"testing"

	"meshtransit.net/client/internal/underlay/underlaytest"
)

// Not parallel: the underlay protector is process-wide.
func TestSourceAddressProbeIsProtected(t *testing.T) {
	underlaytest.Refuse(t)
	_, err := sourceAddressTowards(netip.MustParseAddr("127.0.0.1"))
	underlaytest.RequireProtected(t, "source address probe", err)
}

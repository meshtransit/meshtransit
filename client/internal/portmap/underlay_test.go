package portmap

import (
	"net/http"
	"net/netip"
	"testing"

	"meshtransit.net/client/internal/underlay/underlaytest"
)

// Not parallel: the underlay protector is process-wide.
func TestPortMappingSocketsAreProtected(t *testing.T) {
	underlaytest.Refuse(t)
	loopback := netip.MustParseAddr("127.0.0.1")
	_, err := listenUDP(t.Context(), loopback)
	underlaytest.RequireProtected(t, "NAT-PMP/PCP UDP", err)
	transport, ok := newUPnPHTTPClient().Transport.(*http.Transport)
	if !ok {
		t.Fatal("the UPnP transport is not an *http.Transport")
	}
	_, err = transport.DialContext(t.Context(), "tcp", "127.0.0.1:9")
	underlaytest.RequireProtected(t, "UPnP HTTP transport", err)
}

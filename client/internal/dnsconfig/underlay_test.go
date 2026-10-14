package dnsconfig

import (
	"net/netip"
	"testing"

	"meshtransit.net/client/internal/underlay/underlaytest"
)

// Not parallel: the underlay protector is process-wide.
func TestUpstreamResolverSocketsAreProtected(t *testing.T) {
	underlaytest.Refuse(t)
	upstream := netip.MustParseAddrPort("127.0.0.1:53")
	_, err := exchangeUDP(t.Context(), []byte{0}, upstream)
	underlaytest.RequireProtected(t, "upstream DNS over UDP", err)
	_, err = exchangeTCP(t.Context(), []byte{0}, upstream)
	underlaytest.RequireProtected(t, "upstream DNS over TCP", err)
}

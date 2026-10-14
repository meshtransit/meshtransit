package interchange

import (
	"net/netip"
	"testing"

	"meshtransit.net/client/internal/underlay/underlaytest"
)

// Not parallel: the underlay protector is process-wide.
func TestRelaySocketsAreProtected(t *testing.T) {
	underlaytest.Refuse(t)
	relay := endpoint{host: "relay.example", addr: netip.MustParseAddr("127.0.0.1"), udpPort: 9, tlsPort: 9}
	_, err := dialUDP(t.Context(), relay)
	underlaytest.RequireProtected(t, "relay UDP", err)
	_, err = dialTLS(t.Context(), relay)
	underlaytest.RequireProtected(t, "relay TLS", err)
	_, err = dialWebSocket(t.Context(), relay)
	underlaytest.RequireProtected(t, "relay WebSocket", err)
}

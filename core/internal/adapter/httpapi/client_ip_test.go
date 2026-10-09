package httpapi

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestClientIPResolverIgnoresForwardingFromUntrustedPeer(t *testing.T) {
	t.Parallel()

	resolver, _ := newClientIPResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	request := httptest.NewRequestWithContext(t.Context(), "POST", "https://core.example.test/api", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.9")
	address, err := resolver.Resolve(request)
	if err != nil || address.String() != "192.0.2.10" {
		t.Fatalf("Resolve() = (%s, %v)", address, err)
	}
}

func TestClientIPResolverSelectsLastUntrustedHop(t *testing.T) {
	t.Parallel()

	resolver, _ := newClientIPResolver([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
	})
	request := httptest.NewRequestWithContext(t.Context(), "POST", "https://core.example.test/api", nil)
	request.RemoteAddr = "10.0.0.2:443"
	request.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.9, 172.16.0.3")
	address, err := resolver.Resolve(request)
	if err != nil || address.String() != "198.51.100.9" {
		t.Fatalf("Resolve() = (%s, %v)", address, err)
	}
}

func TestClientIPResolverRejectsMalformedTrustedForwarding(t *testing.T) {
	t.Parallel()

	resolver, _ := newClientIPResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	request := httptest.NewRequestWithContext(t.Context(), "POST", "https://core.example.test/api", nil)
	request.RemoteAddr = "10.0.0.2:443"
	request.Header.Set("X-Forwarded-For", "not-an-ip")
	if _, err := resolver.Resolve(request); err == nil {
		t.Fatal("Resolve() accepted malformed trusted forwarding")
	}
}

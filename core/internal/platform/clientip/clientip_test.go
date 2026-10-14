package clientip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestResolverIgnoresForwardingFromUntrustedPeer(t *testing.T) {
	t.Parallel()

	resolver, _ := NewResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	request := httptest.NewRequestWithContext(t.Context(), "POST", "https://core.example.test/api", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.9")
	address, err := resolver.Resolve(request)
	if err != nil || address.String() != "192.0.2.10" {
		t.Fatalf("Resolve() = (%s, %v)", address, err)
	}
}

func TestResolverSelectsLastUntrustedHop(t *testing.T) {
	t.Parallel()

	resolver, _ := NewResolver([]netip.Prefix{
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

func TestResolverRejectsMalformedTrustedForwarding(t *testing.T) {
	t.Parallel()

	resolver, _ := NewResolver([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	request := httptest.NewRequestWithContext(t.Context(), "POST", "https://core.example.test/api", nil)
	request.RemoteAddr = "10.0.0.2:443"
	request.Header.Set("X-Forwarded-For", "not-an-ip")
	if _, err := resolver.Resolve(request); err == nil {
		t.Fatal("Resolve() accepted malformed trusted forwarding")
	}
}

func TestForwardedByUntrustedPeer(t *testing.T) {
	t.Parallel()
	resolver, err := NewResolver([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		remote string
		header string
		want   bool
	}{
		"untrusted peer forwarding":       {remote: "203.0.113.7:443", header: "X-Forwarded-For", want: true},
		"untrusted peer naming via a CDN": {remote: "203.0.113.7:443", header: "CF-Connecting-IP", want: true},
		"untrusted peer without headers":  {remote: "203.0.113.7:443"},
		"trusted proxy forwarding":        {remote: "10.20.3.4:443", header: "X-Forwarded-For"},
		"unparseable peer":                {remote: "not-an-address", header: "X-Forwarded-For"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			request := &http.Request{RemoteAddr: test.remote, Header: http.Header{}}
			if test.header != "" {
				request.Header.Set(test.header, "198.51.100.9")
			}
			if got := resolver.ForwardedByUntrustedPeer(request); got != test.want {
				t.Fatalf("ForwardedByUntrustedPeer() = %t, want %t", got, test.want)
			}
		})
	}
}

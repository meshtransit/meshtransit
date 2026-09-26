//go:build dexbroker

package dexbroker

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

func TestOIDCOutboundHTTPClientHasBoundedPolicy(t *testing.T) {
	client, transport, err := newOIDCOutboundHTTPClient(GoogleOIDCProviderEndpoints())
	if err != nil {
		t.Fatalf("newOIDCOutboundHTTPClient() error = %v", err)
	}
	t.Cleanup(transport.CloseIdleConnections)
	if client.Timeout != outboundRequestTimeout || transport.Proxy != nil ||
		transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 ||
		transport.TLSHandshakeTimeout != outboundTLSHandshakeTimeout ||
		transport.ResponseHeaderTimeout != outboundResponseHeaderTimeout ||
		transport.MaxResponseHeaderBytes != outboundMaxResponseHeaderBytes ||
		transport.MaxConnsPerHost != outboundMaxConnectionsPerHost ||
		transport.MaxIdleConns != outboundMaxIdleConnections || !transport.DisableCompression {
		t.Fatal("outbound HTTP transport policy mismatch")
	}
	if transport.Protocols == nil || !transport.Protocols.HTTP1() || transport.Protocols.HTTP2() {
		t.Fatal("outbound transport did not constrain protocol to HTTP/1")
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, googleIssuerURL, nil)
	if err != nil {
		t.Fatalf("new redirect request: %v", err)
	}
	if err := client.CheckRedirect(request, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect() error = %v", err)
	}
	roundTripper, ok := client.Transport.(*boundedOutboundRoundTripper)
	if !ok || len(roundTripper.rules) != 3 {
		t.Fatal("outbound endpoint rules mismatch")
	}
}

func TestBoundedOutboundRoundTripperRejectsUnapprovedRequests(t *testing.T) {
	const endpoint = "https://provider.example/token"
	var calls atomic.Int32
	roundTripper := &boundedOutboundRoundTripper{
		base: outboundRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls.Add(1)
			return outboundResponse(request, "{}"), nil
		}),
		rules: map[string]outboundEndpointRule{
			outboundRuleKey(http.MethodPost, endpoint): {
				maxRequestBytes: 8, maxResponseBytes: 8,
			},
		},
	}
	tests := []struct {
		name    string
		method  string
		url     string
		host    string
		body    string
		unknown bool
	}{
		{name: "wrong method", method: http.MethodGet, url: endpoint},
		{name: "wrong url", method: http.MethodPost, url: "https://other.example/token", body: "a"},
		{name: "overridden host", method: http.MethodPost, url: endpoint, host: "other.example", body: "a"},
		{name: "oversized body", method: http.MethodPost, url: endpoint, body: "123456789"},
		{name: "unknown body length", method: http.MethodPost, url: endpoint, body: "a", unknown: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequestWithContext(
				t.Context(), test.method, test.url, strings.NewReader(test.body),
			)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			request.Host = test.host
			if test.unknown {
				request.ContentLength = -1
			}
			assertOutboundPolicyRejected(t, roundTripper, request)
		})
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("base transport calls = %d, want zero", got)
	}
}

func TestBoundedOutboundRoundTripperBoundsResponseAndRemovesCompression(t *testing.T) {
	const endpoint = "https://provider.example/keys"
	var acceptedEncoding string
	base := outboundRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		acceptedEncoding = request.Header.Get("Accept-Encoding")
		return outboundResponse(request, strings.Repeat("x", 9)), nil
	})
	roundTripper := &boundedOutboundRoundTripper{
		base: base,
		rules: map[string]outboundEndpointRule{
			outboundRuleKey(http.MethodGet, endpoint): {maxResponseBytes: 8},
		},
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	request.Header.Set("Accept-Encoding", "gzip")
	assertOutboundPolicyRejected(t, roundTripper, request)
	if acceptedEncoding != "" || request.Header.Get("Accept-Encoding") != "gzip" {
		t.Fatal("compression header filtering mutated the caller or reached the transport")
	}
}

func TestBoundedOutboundRoundTripperClosesResponseReturnedWithError(t *testing.T) {
	const endpoint = "https://provider.example/keys"
	var closed atomic.Bool
	roundTripper := &boundedOutboundRoundTripper{
		base: outboundRoundTripFunc(func(request *http.Request) (*http.Response, error) {
			return &http.Response{
				Body:    closeTrackingBody{Reader: strings.NewReader("discard"), closed: &closed},
				Request: request,
			}, errors.New("transport failure")
		}),
		rules: map[string]outboundEndpointRule{
			outboundRuleKey(http.MethodGet, endpoint): {maxResponseBytes: 8},
		},
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	assertOutboundPolicyRejected(t, roundTripper, request)
	if !closed.Load() {
		t.Fatal("response body was not closed")
	}
}

func TestSecureOutboundDialerRejectsPrivateResolution(t *testing.T) {
	var calls atomic.Int32
	dialer := &secureOutboundDialer{
		resolver: outboundResolverStub{addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}},
		dial: func(context.Context, string, string) (net.Conn, error) {
			calls.Add(1)
			return nil, errors.New("unexpected dial")
		},
		allowedHosts: map[string]struct{}{"provider.example": {}},
	}
	if _, err := dialer.dialContext(t.Context(), "tcp", "provider.example:443"); !errors.Is(err, errOutboundHTTPPolicy) {
		t.Fatalf("dialContext() error = %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Fatalf("dial calls = %d, want zero", got)
	}
}

func TestSecureOutboundDialerUsesValidatedResolvedAddress(t *testing.T) {
	var peer net.Conn
	var dialedAddress string
	dialer := &secureOutboundDialer{
		resolver: outboundResolverStub{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}},
		dial: func(_ context.Context, _ string, address string) (net.Conn, error) {
			dialedAddress = address
			connection, other := net.Pipe()
			peer = other
			return connection, nil
		},
		allowedHosts: map[string]struct{}{"provider.example": {}},
	}
	connection, err := dialer.dialContext(t.Context(), "tcp", "provider.example:443")
	if err != nil {
		t.Fatalf("dialContext() error = %v", err)
	}
	if dialedAddress != "8.8.8.8:443" {
		t.Fatalf("dialed address = %q", dialedAddress)
	}
	_ = connection.Close()
	_ = peer.Close()
}

func TestValidOutboundIPRejectsSpecialUseRanges(t *testing.T) {
	tests := []struct {
		address string
		valid   bool
	}{
		{address: "8.8.8.8", valid: true},
		{address: "2606:4700:4700::1111", valid: true},
		{address: "100.64.0.1"},
		{address: "127.0.0.1"},
		{address: "169.254.169.254"},
		{address: "192.0.2.1"},
		{address: "198.18.0.1"},
		{address: "2001:db8::1"},
		{address: "fd00::1"},
	}
	for _, test := range tests {
		t.Run(test.address, func(t *testing.T) {
			if got := validOutboundIP(netip.MustParseAddr(test.address)); got != test.valid {
				t.Fatalf("validOutboundIP() = %t, want %t", got, test.valid)
			}
		})
	}
}

type outboundRoundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip outboundRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func assertOutboundPolicyRejected(
	t *testing.T,
	roundTripper http.RoundTripper,
	request *http.Request,
) {
	t.Helper()
	response, err := roundTripper.RoundTrip(request)
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if !errors.Is(err, errOutboundHTTPPolicy) {
		t.Fatalf("RoundTrip() error = %v", err)
	}
}

type closeTrackingBody struct {
	*strings.Reader
	closed *atomic.Bool
}

func (body closeTrackingBody) Close() error {
	body.closed.Store(true)
	return nil
}

func outboundResponse(request *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    request,
	}
}

type outboundResolverStub struct {
	addresses []netip.Addr
	err       error
}

func (resolver outboundResolverStub) LookupNetIP(
	context.Context,
	string,
	string,
) ([]netip.Addr, error) {
	return append([]netip.Addr(nil), resolver.addresses...), resolver.err
}

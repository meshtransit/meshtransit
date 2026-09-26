//go:build dexbroker

package dexbroker

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"
)

const (
	outboundHTTPPolicyVersion            = "oidc-outbound-http/v1"
	outboundRequestTimeout               = 10 * time.Second
	outboundDialTimeout                  = 3 * time.Second
	outboundTLSHandshakeTimeout          = 3 * time.Second
	outboundResponseHeaderTimeout        = 5 * time.Second
	outboundIdleConnectionTimeout        = 30 * time.Second
	outboundMaxResponseHeaderBytes       = 32 * 1024
	outboundMaxConnectionsPerHost        = 4
	outboundMaxIdleConnections           = 4
	outboundMaxResolvedIPs               = 16
	outboundDiscoveryResponseBytes int64 = 64 * 1024
	outboundTokenRequestBytes      int64 = 32 * 1024
	outboundTokenResponseBytes     int64 = 64 * 1024
	outboundJWKSResponseBytes      int64 = 256 * 1024

	googleIssuerURL        = "https://accounts.google.com"
	googleAuthorizationURL = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL         = "https://oauth2.googleapis.com/token" //nolint:gosec // Public OIDC endpoint, not a token or credential.
	googleJWKSURL          = "https://www.googleapis.com/oauth2/v3/certs"
)

var errOutboundHTTPPolicy = errors.New("dex broker outbound http policy rejected request")

var blockedOutboundPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// GoogleOIDCProviderEndpoints returns a fresh value containing the exact
// Phase 1 Google endpoint set. Future providers supply their own immutable set.
func GoogleOIDCProviderEndpoints() OIDCProviderEndpoints {
	return OIDCProviderEndpoints{
		DiscoveryURL:     googleIssuerURL + "/.well-known/openid-configuration",
		AuthorizationURL: googleAuthorizationURL,
		TokenURL:         googleTokenURL,
		JWKSURL:          googleJWKSURL,
	}
}

type outboundEndpointRule struct {
	maxRequestBytes  int64
	maxResponseBytes int64
}

type outboundHTTPClients struct {
	clients    map[string]*http.Client
	transports []*http.Transport
	closeOnce  sync.Once
}

func newOIDCOutboundHTTPClients(configuration componentConfiguration) (*outboundHTTPClients, error) {
	owned := &outboundHTTPClients{
		clients:    make(map[string]*http.Client, len(configuration.connectors)),
		transports: make([]*http.Transport, 0, len(configuration.connectors)),
	}
	for _, connector := range configuration.connectors {
		client, transport, err := newOIDCOutboundHTTPClient(connector.endpoints)
		if err != nil {
			owned.close()
			return nil, errOutboundHTTPPolicy
		}
		if _, exists := owned.clients[connector.id]; exists {
			transport.CloseIdleConnections()
			owned.close()
			return nil, errOutboundHTTPPolicy
		}
		owned.clients[connector.id] = client
		owned.transports = append(owned.transports, transport)
	}
	return owned, nil
}

func newOIDCOutboundHTTPClient(
	endpoints OIDCProviderEndpoints,
) (*http.Client, *http.Transport, error) {
	if !validProviderEndpoints(issuerFromDiscoveryURL(endpoints.DiscoveryURL), endpoints) {
		return nil, nil, errOutboundHTTPPolicy
	}
	rules := map[string]outboundEndpointRule{
		outboundRuleKey(http.MethodGet, endpoints.DiscoveryURL): {
			maxResponseBytes: outboundDiscoveryResponseBytes,
		},
		outboundRuleKey(http.MethodPost, endpoints.TokenURL): {
			maxRequestBytes: outboundTokenRequestBytes, maxResponseBytes: outboundTokenResponseBytes,
		},
		outboundRuleKey(http.MethodGet, endpoints.JWKSURL): {
			maxResponseBytes: outboundJWKSResponseBytes,
		},
	}
	allowedHosts := make(map[string]struct{}, 3)
	for _, endpoint := range []string{endpoints.DiscoveryURL, endpoints.TokenURL, endpoints.JWKSURL} {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Port() != "" {
			return nil, nil, errOutboundHTTPPolicy
		}
		allowedHosts[parsed.Hostname()] = struct{}{}
	}

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	dialer := &secureOutboundDialer{
		resolver: net.DefaultResolver,
		dial: (&net.Dialer{
			Timeout: outboundDialTimeout, KeepAlive: outboundIdleConnectionTimeout,
		}).DialContext,
		allowedHosts: allowedHosts,
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.dialContext,
		ForceAttemptHTTP2:      false,
		Protocols:              protocols,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    outboundTLSHandshakeTimeout,
		ResponseHeaderTimeout:  outboundResponseHeaderTimeout,
		ExpectContinueTimeout:  time.Second,
		IdleConnTimeout:        outboundIdleConnectionTimeout,
		MaxResponseHeaderBytes: outboundMaxResponseHeaderBytes,
		MaxConnsPerHost:        outboundMaxConnectionsPerHost,
		MaxIdleConns:           outboundMaxIdleConnections,
		MaxIdleConnsPerHost:    outboundMaxConnectionsPerHost,
		DisableCompression:     true,
	}
	client := &http.Client{
		Transport: &boundedOutboundRoundTripper{base: transport, rules: rules},
		Timeout:   outboundRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, transport, nil
}

func issuerFromDiscoveryURL(discoveryURL string) string {
	const suffix = "/.well-known/openid-configuration"
	if len(discoveryURL) <= len(suffix) || discoveryURL[len(discoveryURL)-len(suffix):] != suffix {
		return ""
	}
	return discoveryURL[:len(discoveryURL)-len(suffix)]
}

func (clients *outboundHTTPClients) close() {
	if clients == nil {
		return
	}
	clients.closeOnce.Do(func() {
		for _, transport := range clients.transports {
			transport.CloseIdleConnections()
		}
	})
}

type boundedOutboundRoundTripper struct {
	base  http.RoundTripper
	rules map[string]outboundEndpointRule
}

func (roundTripper *boundedOutboundRoundTripper) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	if roundTripper == nil || roundTripper.base == nil || request == nil || request.URL == nil ||
		request.Context() == nil {
		return nil, errOutboundHTTPPolicy
	}
	rule, exists := roundTripper.rules[outboundRuleKey(request.Method, request.URL.String())]
	validHost := request.Host == "" || request.Host == request.URL.Host
	validBody := request.ContentLength >= 0 && request.ContentLength <= rule.maxRequestBytes
	if !exists || !validHost || !validBody || (rule.maxRequestBytes == 0 && request.Body != nil) {
		return nil, errOutboundHTTPPolicy
	}
	forward := request.Clone(request.Context())
	forward.Header = request.Header.Clone()
	forward.Header.Del("Accept-Encoding")
	response, err := roundTripper.base.RoundTrip(forward)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, errOutboundHTTPPolicy
	}
	if response == nil || response.Body == nil {
		return nil, errOutboundHTTPPolicy
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, rule.maxResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || int64(len(body)) > rule.maxResponseBytes {
		clear(body)
		return nil, errOutboundHTTPPolicy
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	return response, nil
}

func outboundRuleKey(method, endpoint string) string {
	return method + "\x00" + endpoint
}

type outboundIPResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type outboundDialFunc func(context.Context, string, string) (net.Conn, error)

type secureOutboundDialer struct {
	resolver     outboundIPResolver
	dial         outboundDialFunc
	allowedHosts map[string]struct{}
}

func (dialer *secureOutboundDialer) dialContext(
	ctx context.Context,
	network string,
	address string,
) (net.Conn, error) {
	if dialer == nil || ctx == nil || ctx.Err() != nil || dialer.resolver == nil || dialer.dial == nil {
		return nil, errOutboundHTTPPolicy
	}
	host, port, err := net.SplitHostPort(address)
	_, allowed := dialer.allowedHosts[host]
	if err != nil || !allowed || port != "443" || (network != "tcp" && network != "tcp4" && network != "tcp6") {
		return nil, errOutboundHTTPPolicy
	}
	addresses, err := dialer.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 || len(addresses) > outboundMaxResolvedIPs {
		return nil, errOutboundHTTPPolicy
	}
	for index := range addresses {
		addresses[index] = addresses[index].Unmap()
		if !validOutboundIP(addresses[index]) {
			return nil, errOutboundHTTPPolicy
		}
	}
	for _, ip := range addresses {
		connection, dialErr := dialer.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if dialErr == nil {
			return connection, nil
		}
		if ctx.Err() != nil {
			return nil, errOutboundHTTPPolicy
		}
	}
	return nil, errOutboundHTTPPolicy
}

func validOutboundIP(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, prefix := range blockedOutboundPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

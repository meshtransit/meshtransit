//go:build dexbroker

package dexbroker

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
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
	outboundUserInfoResponseBytes  int64 = 64 * 1024

	googleIssuerURL        = "https://accounts.google.com"
	googleAuthorizationURL = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL         = "https://oauth2.googleapis.com/token" //nolint:gosec // Public OIDC endpoint, not a token or credential.
	googleJWKSURL          = "https://www.googleapis.com/oauth2/v3/certs"
)

var errOutboundHTTPPolicy = errors.New("dex broker outbound http policy rejected request")

// blockedOutboundPrefixes are never reached, whatever a connector allows:
// metadata services, loopback, link-local, documentation and special
// ranges, and IPv6 forms that carry an IPv4 address (NAT64, 6to4, Teredo,
// IPv4-compatible).
var blockedOutboundPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.100.100.100/32"),
	netip.MustParsePrefix("100.100.100.200/32"),
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::ffff:0:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// privateOutboundPrefixes are reached only inside a range a connector lists
// (V1-22: an identity provider on a private network).
var privateOutboundPrefixes = [...]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// sharedAddressSpace (100.64/10) may be a mesh overlay or carrier NAT: only
// a range inside it is allowed, never all of it.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// minimumSharedAddressBits keeps a listed part of 100.64/10 to a /16 at
// most, so the whole space cannot be listed in pieces either.
const minimumSharedAddressBits = 16

// validPrivateNetwork is a masked range inside one private range.
func validPrivateNetwork(prefix netip.Prefix) bool {
	if !prefix.IsValid() || prefix.Masked() != prefix {
		return false
	}
	if sharedAddressSpace.Contains(prefix.Addr()) && prefix.Bits() < minimumSharedAddressBits {
		return false
	}
	for _, private := range privateOutboundPrefixes {
		if private.Bits() <= prefix.Bits() && private.Contains(prefix.Addr()) {
			return true
		}
	}
	return false
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

// newOIDCOutboundHTTPClients builds one client per connector. Requests are
// cancelled when lifetime ends: Dex opens connectors with a background
// context, so a provider that hangs would otherwise hold up shutdown.
func newOIDCOutboundHTTPClients(
	lifetime context.Context,
	configuration componentConfiguration,
) (*outboundHTTPClients, error) {
	if lifetime == nil {
		return nil, errOutboundHTTPPolicy
	}
	owned := &outboundHTTPClients{
		clients:    make(map[string]*http.Client, len(configuration.connectors)),
		transports: make([]*http.Transport, 0, len(configuration.connectors)),
	}
	for _, connector := range configuration.connectors {
		client, transport, err := newOIDCOutboundHTTPClient(connector.endpoints, outboundConnectorPolicy{
			caPEM: connector.caPEM, privateNetworks: connector.privateNets,
			generic: connector.issuer != googleIssuerURL || connector.hasOptions(), tokenAuth: connector.tokenAuth,
		})
		if err != nil {
			owned.close()
			return nil, errOutboundHTTPPolicy
		}
		if _, exists := owned.clients[connector.id]; exists {
			transport.CloseIdleConnections()
			owned.close()
			return nil, errOutboundHTTPPolicy
		}
		if bounded, ok := client.Transport.(*boundedOutboundRoundTripper); ok {
			bounded.lifetime = lifetime
		}
		owned.clients[connector.id] = client
		owned.transports = append(owned.transports, transport)
	}
	return owned, nil
}

// outboundConnectorPolicy is what a connector adds to the outbound rules:
// a private CA and the private ranges its provider is reached in.
type outboundConnectorPolicy struct {
	caPEM           []byte
	privateNetworks []netip.Prefix
	// generic is set for every connector but Google's: it turns on the
	// claim guard (outbound_claims.go).
	generic   bool
	tokenAuth TokenAuth
}

func newOIDCOutboundHTTPClient(
	endpoints OIDCProviderEndpoints,
	policy outboundConnectorPolicy,
) (*http.Client, *http.Transport, error) {
	if !validProviderEndpoints(issuerFromDiscoveryURL(endpoints.DiscoveryURL), endpoints) {
		return nil, nil, errOutboundHTTPPolicy
	}
	for _, prefix := range policy.privateNetworks {
		if !validPrivateNetwork(prefix) {
			return nil, nil, errOutboundHTTPPolicy
		}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(policy.caPEM) != 0 {
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(policy.caPEM) {
			return nil, nil, errOutboundHTTPPolicy
		}
		tlsConfig.RootCAs = roots
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
	dialed := []string{endpoints.DiscoveryURL, endpoints.TokenURL, endpoints.JWKSURL}
	if endpoints.UserInfoURL != "" {
		rules[outboundRuleKey(http.MethodGet, endpoints.UserInfoURL)] = outboundEndpointRule{
			maxResponseBytes: outboundUserInfoResponseBytes,
		}
		dialed = append(dialed, endpoints.UserInfoURL)
	}
	// Exact host:port pairs: a provider's host on another port is refused.
	allowedHosts := make(map[string]struct{}, len(dialed))
	for _, endpoint := range dialed {
		parsed, err := url.Parse(endpoint)
		if err != nil || !validEndpointPort(endpoint) {
			return nil, nil, errOutboundHTTPPolicy
		}
		port := parsed.Port()
		if port == "" {
			port = "443"
		}
		allowedHosts[net.JoinHostPort(parsed.Hostname(), port)] = struct{}{}
	}

	var guard *outboundClaimGuard
	if policy.generic {
		guard = newOutboundClaimGuard(endpoints, policy.tokenAuth)
	}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	dialer := &secureOutboundDialer{
		resolver: net.DefaultResolver,
		dial: (&net.Dialer{
			Timeout: outboundDialTimeout, KeepAlive: outboundIdleConnectionTimeout,
		}).DialContext,
		allowedHosts:    allowedHosts,
		privateNetworks: slices.Clone(policy.privateNetworks),
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.dialContext,
		ForceAttemptHTTP2:      false,
		Protocols:              protocols,
		TLSClientConfig:        tlsConfig,
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
		Transport: &boundedOutboundRoundTripper{base: transport, rules: rules, guard: guard},
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
	// guard is nil for Google, whose behaviour predates V1-22.
	guard *outboundClaimGuard
	// lifetime, when set, cancels requests still running when it ends.
	lifetime context.Context
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
	requestCtx := request.Context()
	if roundTripper.lifetime != nil {
		bounded, cancel := context.WithCancel(requestCtx)
		defer cancel()
		defer context.AfterFunc(roundTripper.lifetime, cancel)()
		requestCtx = bounded
	}
	forward := request.Clone(requestCtx)
	forward.Header = request.Header.Clone()
	forward.Header.Del("Accept-Encoding")
	if roundTripper.guard != nil && request.Body != nil {
		requestBody, err := io.ReadAll(io.LimitReader(request.Body, rule.maxRequestBytes+1))
		_ = request.Body.Close()
		if err != nil || int64(len(requestBody)) > rule.maxRequestBytes ||
			!roundTripper.guard.checkRequest(request, requestBody) {
			return nil, errOutboundHTTPPolicy
		}
		forward.Body = io.NopCloser(bytes.NewReader(requestBody))
		forward.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(requestBody)), nil }
		forward.ContentLength = int64(len(requestBody))
	} else if roundTripper.guard != nil && !roundTripper.guard.checkRequest(request, nil) {
		return nil, errOutboundHTTPPolicy
	}
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
	if readErr != nil || closeErr != nil || int64(len(body)) > rule.maxResponseBytes ||
		!roundTripper.guard.checkResponse(request, response, body) {
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
	resolver        outboundIPResolver
	dial            outboundDialFunc
	allowedHosts    map[string]struct{}
	privateNetworks []netip.Prefix
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
	_, allowed := dialer.allowedHosts[net.JoinHostPort(host, port)]
	if err != nil || !allowed || (network != "tcp" && network != "tcp4" && network != "tcp6") {
		return nil, errOutboundHTTPPolicy
	}
	addresses, err := dialer.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 || len(addresses) > outboundMaxResolvedIPs {
		return nil, errOutboundHTTPPolicy
	}
	for index := range addresses {
		addresses[index] = addresses[index].Unmap()
		if !validOutboundIP(addresses[index], dialer.privateNetworks) {
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

// validOutboundIP refuses the always-blocked ranges, and a private address
// outside the ranges the connector lists.
func validOutboundIP(ip netip.Addr, privateNetworks []netip.Prefix) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, prefix := range blockedOutboundPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	private := ip.IsPrivate()
	for _, prefix := range privateOutboundPrefixes {
		private = private || prefix.Contains(ip)
	}
	if !private {
		return true
	}
	for _, prefix := range privateNetworks {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

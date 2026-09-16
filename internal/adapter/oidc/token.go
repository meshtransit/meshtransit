package oidc

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

var (
	// ErrInvalidAuthenticator rejects unsafe client/security policy before I/O.
	ErrInvalidAuthenticator = errors.New("oidc token: invalid authenticator")
	// ErrTokenRejected conceals malformed, forged, or mismatched provider evidence.
	ErrTokenRejected = errors.New("oidc token: rejected")
	// ErrTokenUnavailable conceals transport/cleanup failure without raw error text.
	ErrTokenUnavailable = errors.New("oidc token: unavailable")
)

// BasicSecret is resident confidential-client material loaded through secret custody.
// It never belongs in config JSON, source, metrics, URLs, or browser storage.
type BasicSecret struct{ value string }

// NewBasicSecret requires 32–4096 printable ASCII bytes; no local-login fallback.
func NewBasicSecret(value string) (BasicSecret, error) {
	if !validTokenASCII(value, 4096) || len(value) < 32 {
		return BasicSecret{}, ErrInvalidAuthenticator
	}
	return BasicSecret{value: value}, nil
}

// String prevents accidental credential formatting.
func (BasicSecret) String() string { return "[REDACTED]" }

// GoString prevents detailed credential formatting.
func (BasicSecret) GoString() string { return "oidc.BasicSecret([REDACTED])" }

// LogValue prevents structured credential formatting.
func (BasicSecret) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// TokenOptions bounds one POST plus trusted JWKS validation under one deadline.
// No cache extends signing-key trust. Clock is injected; MaxTokenAge/ClockSkew
// apply to whole-second NumericDates, never to the durable claim deadline.
type TokenOptions struct {
	Timeout, MaxTokenAge, ClockSkew time.Duration
	Clock                           oidcauth.StartClock
}

// Authenticator validates ID tokens for one exact confidential browser route.
// Initial credential method is client_secret_basic; private_key_jwt remains
// fail-closed until its separately qualified assertion/rotation boundary exists.
type Authenticator struct {
	route   oidcauth.Route
	secret  BasicSecret
	options TokenOptions
	client  doer
}

// NewAuthenticator constructs an owned TLS-only, no-proxy, no-redirect HTTP client.
// It performs no network I/O and never accepts endpoints from token content.
func NewAuthenticator(options TokenOptions, route oidcauth.Route, secret BasicSecret) (*Authenticator, error) {
	if !validTokenOptions(options) || !route.IsValid() || route.ClientAuthMethod() != "client_secret_basic" || len(secret.value) < 32 || !validTokenASCII(secret.value, 4096) {
		return nil, ErrInvalidAuthenticator
	}
	dialer := &net.Dialer{Timeout: options.Timeout, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, DialContext: dialer.DialContext, ForceAttemptHTTP2: true,
		DisableCompression: true, MaxIdleConns: 16, MaxIdleConnsPerHost: 4, MaxConnsPerHost: 16,
		IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: options.Timeout,
		ResponseHeaderTimeout: options.Timeout, MaxResponseHeaderBytes: 32 * 1024,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	client := &http.Client{Transport: transport, Timeout: options.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Authenticator{route: route, secret: secret, options: options, client: client}, nil
}
func validTokenOptions(options TokenOptions) bool {
	validTimeout := options.Timeout > 0 && options.Timeout <= 30*time.Second
	validAge := options.MaxTokenAge > 0 && options.MaxTokenAge <= 10*time.Minute && options.MaxTokenAge%time.Second == 0
	validSkew := options.ClockSkew >= 0 && options.ClockSkew <= time.Minute && options.ClockSkew%time.Second == 0
	return validTimeout && validAge && validSkew && options.Clock != nil
}

// Authenticate POSTs code once then verifies the ID token with bounded trusted
// JWKS fetches. Provider access/refresh tokens are ignored, never returned or used
// as authority. Core independently verifies nonce HMAC after this port completes.
func (authenticator *Authenticator) Authenticate(ctx context.Context, request oidcauth.ExchangeRequest) (oidcauth.TokenEvidence, error) {
	if ctx == nil || authenticator == nil || authenticator.client == nil || !request.IsValid() || !sameTokenRoute(authenticator.route, request.Route()) {
		return oidcauth.TokenEvidence{}, ErrInvalidAuthenticator
	}
	ctx, cancel := context.WithTimeout(ctx, authenticator.options.Timeout)
	defer cancel()
	if ctx.Err() != nil {
		return oidcauth.TokenEvidence{}, errors.Join(ErrTokenUnavailable, ctx.Err())
	}
	return authenticator.exchangeToken(ctx, request.Code(), request.Verifier())
}

// exchangeToken is internal to the trusted adapter, not an alternative public
// constructor or receipt bypass. Authenticate validates its originating request.
func (authenticator *Authenticator) exchangeToken(ctx context.Context, code oidcauth.Code, verifier oidcauth.Verifier) (oidcauth.TokenEvidence, error) {
	if ctx.Err() != nil {
		return oidcauth.TokenEvidence{}, errors.Join(ErrTokenUnavailable, ctx.Err())
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code.Encoded()}, "redirect_uri": {authenticator.route.RedirectURI()}, "code_verifier": {verifier.Encoded()}}
	body := form.Encode()
	if len(body) > 24*1024 {
		return oidcauth.TokenEvidence{}, ErrTokenRejected
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, authenticator.route.TokenEndpoint(), strings.NewReader(body))
	if err != nil {
		return oidcauth.TokenEvidence{}, ErrInvalidAuthenticator
	}
	// RFC 6749 section 2.3.1 requires form-encoding before HTTP Basic encoding.
	httpRequest.SetBasicAuth(url.QueryEscape(authenticator.route.OIDCClientID()), url.QueryEscape(authenticator.secret.value))
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpRequest.Header.Set("Accept", "application/json")
	raw, err := authenticator.readJSON(ctx, httpRequest, 64*1024)
	if err != nil {
		return oidcauth.TokenEvidence{}, err
	}
	defer clear(raw)
	values, err := tokenObject(raw, 32)
	if err != nil {
		return oidcauth.TokenEvidence{}, ErrTokenRejected
	}
	var token string
	if _, exists := values["error"]; exists {
		return oidcauth.TokenEvidence{}, ErrTokenRejected
	}
	if !tokenRequired(values, "id_token", &token) || len(token) == 0 || len(token) > maximumIDTokenBytes {
		return oidcauth.TokenEvidence{}, ErrTokenRejected
	}
	evidence, err := authenticator.validateIDToken(ctx, token)
	if err != nil {
		return oidcauth.TokenEvidence{}, err
	}
	if ctx.Err() != nil || !authenticator.options.Clock.Now().Before(evidence.ExpiresAt()) {
		return oidcauth.TokenEvidence{}, errors.Join(ErrTokenRejected, ctx.Err())
	}
	return evidence, nil
}

// readJSON joins exactly one Close before any positive result, reads at most max+1,
// and never exposes raw network/JSON/URL errors. It neither retries nor drains an
// unbounded provider body; compression and ambiguous content types reject.
func (authenticator *Authenticator) readJSON(ctx context.Context, request *http.Request, maximum int64) (body []byte, resultErr error) {
	response, err := authenticator.client.Do(request)
	if response != nil && response.Body != nil {
		defer func() {
			if closeErr := response.Body.Close(); closeErr != nil {
				clear(body)
				body, resultErr = nil, errors.Join(ErrTokenUnavailable, ctx.Err())
			}
		}()
	}
	if err != nil || response == nil || response.Body == nil {
		return nil, errors.Join(ErrTokenUnavailable, ctx.Err())
	}
	validHeaders := len(response.Header.Values("Content-Type")) == 1 && isJSONContentType(response.Header.Get("Content-Type")) && len(response.Header.Values("Content-Encoding")) == 0
	if response.StatusCode != http.StatusOK || !validHeaders || response.Uncompressed || response.ContentLength > maximum {
		return nil, ErrTokenRejected
	}
	body, err = io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil || ctx.Err() != nil {
		clear(body)
		return nil, errors.Join(ErrTokenUnavailable, ctx.Err())
	}
	if int64(len(body)) > maximum {
		clear(body)
		return nil, ErrTokenRejected
	}
	return body, nil
}

// Close joins idle connection cleanup for the composition owner; admission must
// stop/drain first. Active request cancellation belongs to its request context.
func (authenticator *Authenticator) Close() {
	if authenticator == nil {
		return
	}
	if client, ok := authenticator.client.(*http.Client); ok {
		client.CloseIdleConnections()
	}
}

// String prevents accidental credential/route formatting.
func (*Authenticator) String() string { return "[REDACTED]" }

// GoString prevents detailed credential/route formatting.
func (*Authenticator) GoString() string { return "oidc.Authenticator([REDACTED])" }

// LogValue prevents structured credential/route formatting.
func (*Authenticator) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func sameTokenRoute(expected, actual oidcauth.Route) bool {
	identities := expected.DeploymentID() == actual.DeploymentID() && expected.WorkspaceID() == actual.WorkspaceID() && expected.ProviderID() == actual.ProviderID() && expected.ClientID() == actual.ClientID()
	generations := expected.ProviderGeneration() == actual.ProviderGeneration() && expected.RecoveryEpoch() == actual.RecoveryEpoch()
	endpoints := expected.Issuer() == actual.Issuer() && expected.DiscoveryURI() == actual.DiscoveryURI() && expected.AuthorizationEndpoint() == actual.AuthorizationEndpoint() && expected.TokenEndpoint() == actual.TokenEndpoint() && expected.JWKSURI() == actual.JWKSURI()
	client := expected.OIDCClientID() == actual.OIDCClientID() && expected.ClientAuthMethod() == actual.ClientAuthMethod() && slices.Equal(expected.Scopes(), actual.Scopes()) && slices.Equal(expected.AllowedAlgorithms(), actual.AllowedAlgorithms())
	redirect := expected.RedirectID() == actual.RedirectID() && expected.RedirectURI() == actual.RedirectURI() && expected.ReturnRouteID() == actual.ReturnRouteID()
	return identities && generations && endpoints && client && redirect
}
func validTokenASCII(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character >= 0x7f {
			return false
		}
	}
	return true
}

var _ oidcauth.TokenAuthenticator = (*Authenticator)(nil)

package oidcauth

import (
	"errors"
	"log/slog"
	"net/url"
	"slices"
	"strings"
)

var (
	// ErrProviderMismatch reports discovery evidence outside the configured trust anchor.
	ErrProviderMismatch = errors.New("oidc auth: provider metadata mismatch")
	// ErrUnsupportedProvider reports a provider that cannot satisfy client policy.
	ErrUnsupportedProvider = errors.New("oidc auth: provider capability is unsupported")
	// ErrInvalidAuthorizationRequest reports malformed transaction input.
	ErrInvalidAuthorizationRequest = errors.New("oidc auth: invalid authorization request")
)

// AuthorizationRequest contains a secret-bearing redirect and always formats redacted.
type AuthorizationRequest struct{ location string }

// NewAuthorizationRequest binds exact route, discovery, and transaction secrets.
func NewAuthorizationRequest(
	route Route,
	metadata Metadata,
	secrets Secrets,
) (AuthorizationRequest, error) {
	if !route.IsValid() || !metadata.IsValid() || !secrets.IsValid() {
		return AuthorizationRequest{}, ErrInvalidAuthorizationRequest
	}
	if metadata.issuer != route.issuer ||
		metadata.authorizationEndpoint != route.authorizationEndpoint ||
		metadata.tokenEndpoint != route.tokenEndpoint ||
		metadata.jwksURI != route.jwksURI {
		return AuthorizationRequest{}, ErrProviderMismatch
	}
	if !slices.Contains(metadata.tokenAuthMethods, route.clientAuthMethod) ||
		!hasIntersection(metadata.idTokenSigningAlgorithms, route.allowedAlgorithms) {
		return AuthorizationRequest{}, ErrUnsupportedProvider
	}
	endpoint, err := url.Parse(metadata.authorizationEndpoint)
	if err != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" {
		return AuthorizationRequest{}, ErrInvalidAuthorizationRequest
	}
	query := url.Values{}
	query.Set("client_id", route.oidcClientID)
	if route.connectorID != "" {
		query.Set("connector_id", route.connectorID)
	}
	query.Set("code_challenge", secrets.verifier.Challenge())
	query.Set("code_challenge_method", "S256")
	query.Set("nonce", secrets.nonce.Encoded())
	query.Set("redirect_uri", route.redirectURI)
	query.Set("response_mode", "query")
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(route.scopes, " "))
	query.Set("state", secrets.state.Encoded())
	endpoint.RawQuery = query.Encode()
	request := AuthorizationRequest{location: endpoint.String()}
	if !request.IsValid() {
		return AuthorizationRequest{}, ErrInvalidAuthorizationRequest
	}
	return request, nil
}

// Location returns the secret-bearing browser redirect. Callers must never log it.
func (request AuthorizationRequest) Location() string { return request.location }

// IsValid reports whether the request is a bounded HTTPS redirect.
func (request AuthorizationRequest) IsValid() bool {
	parsed, err := url.Parse(request.location)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Fragment != "" || parsed.RawQuery == "" || len(request.location) > 8192 {
		return false
	}
	query := parsed.Query()
	for _, name := range []string{
		"client_id", "code_challenge", "code_challenge_method", "nonce", "redirect_uri",
		"response_mode", "response_type", "scope", "state",
	} {
		if len(query[name]) != 1 || query.Get(name) == "" {
			return false
		}
	}
	expectedFields := 9
	connectorBound := false
	if values := query["connector_id"]; len(values) > 0 {
		if len(values) != 1 || !validRouteID(values[0]) {
			return false
		}
		connectorBound = true
		expectedFields++
	}
	federatedScope := slices.Contains(strings.Split(query.Get("scope"), " "), "federated:id")
	return connectorBound == federatedScope && len(query) == expectedFields && query.Get("code_challenge_method") == "S256" &&
		query.Get("response_mode") == "query" && query.Get("response_type") == "code"
}

// String prevents accidental redirect disclosure.
func (AuthorizationRequest) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed redirect disclosure.
func (AuthorizationRequest) GoString() string {
	return "oidcauth.AuthorizationRequest([REDACTED])"
}

// LogValue prevents accidental structured-log redirect disclosure.
func (AuthorizationRequest) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func hasIntersection(left, right []string) bool {
	for _, candidate := range left {
		if slices.Contains(right, candidate) {
			return true
		}
	}
	return false
}

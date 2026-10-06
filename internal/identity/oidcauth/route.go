package oidcauth

import (
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/meshtransit/meshtransit/internal/deployment"
)

const (
	maximumURLBytes      = 2048
	maximumClientIDBytes = 255
	maximumScopes        = 32
	maximumAlgorithms    = 8
)

var (
	// ErrInvalidRoute reports an unsafe or incomplete configured client route.
	ErrInvalidRoute = errors.New("oidc auth: invalid client route")
	// ErrInvalidMetadata reports invalid or unsupported discovered provider metadata.
	ErrInvalidMetadata = errors.New("oidc auth: invalid provider metadata")
)

// RouteParams contains one exact Core-controlled browser login route.
type RouteParams struct {
	DeploymentID          deployment.ID
	ProviderID            ProviderID
	ClientID              ClientID
	ProviderGeneration    int64
	RecoveryEpoch         int64
	Issuer                string
	DiscoveryURI          string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string
	OIDCClientID          string
	ConnectorID           string
	ClientKind            string
	ClientAuthMethod      string
	Scopes                []string
	AllowedAlgorithms     []string
	RedirectID            string
	RedirectURI           string
	ReturnRouteID         string
}

// Route is an immutable provider/client login trust decision. It names no
// Workspace: Core binds each Session to a Workspace chosen for the Account.
type Route struct {
	deploymentID          deployment.ID
	providerID            ProviderID
	clientID              ClientID
	providerGeneration    int64
	recoveryEpoch         int64
	issuer                string
	discoveryURI          string
	authorizationEndpoint string
	tokenEndpoint         string
	jwksURI               string
	oidcClientID          string
	connectorID           string
	clientAuthMethod      string
	scopes                []string
	allowedAlgorithms     []string
	redirectID            string
	redirectURI           string
	returnRouteID         string
}

// NewRoute validates and defensively copies one configured browser route.
func NewRoute(params RouteParams) (Route, error) {
	if !params.DeploymentID.IsValid() ||
		!params.ProviderID.IsValid() || !params.ClientID.IsValid() ||
		params.ProviderGeneration <= 0 || params.RecoveryEpoch <= 0 ||
		params.ClientKind != "confidential" || !validClientAuthMethod(params.ClientAuthMethod) ||
		!validBoundedValue(params.OIDCClientID, maximumClientIDBytes) ||
		!validConnectorBinding(params.ConnectorID, params.Scopes) ||
		!validRouteID(params.RedirectID) || !validRouteID(params.ReturnRouteID) ||
		!validHTTPSURL(params.Issuer, true) || !validHTTPSURL(params.DiscoveryURI, false) ||
		!validHTTPSURL(params.AuthorizationEndpoint, false) ||
		!validHTTPSURL(params.TokenEndpoint, false) ||
		!validHTTPSURL(params.JWKSURI, false) || !validHTTPSURL(params.RedirectURI, false) ||
		!validScopes(params.Scopes) || !validAlgorithms(params.AllowedAlgorithms) {
		return Route{}, ErrInvalidRoute
	}
	return Route{
		deploymentID:          params.DeploymentID,
		providerID:            params.ProviderID,
		clientID:              params.ClientID,
		providerGeneration:    params.ProviderGeneration,
		recoveryEpoch:         params.RecoveryEpoch,
		issuer:                params.Issuer,
		discoveryURI:          params.DiscoveryURI,
		authorizationEndpoint: params.AuthorizationEndpoint,
		tokenEndpoint:         params.TokenEndpoint,
		jwksURI:               params.JWKSURI,
		oidcClientID:          params.OIDCClientID,
		connectorID:           params.ConnectorID,
		clientAuthMethod:      params.ClientAuthMethod,
		scopes:                slices.Clone(params.Scopes),
		allowedAlgorithms:     slices.Clone(params.AllowedAlgorithms),
		redirectID:            params.RedirectID,
		redirectURI:           params.RedirectURI,
		returnRouteID:         params.ReturnRouteID,
	}, nil
}

// Binding returns the exact authority authenticated by a verifier envelope.
func (route Route) Binding(transactionID TransactionID) (Binding, error) {
	binding := Binding{
		DeploymentID: route.deploymentID,
		ProviderID:   route.providerID, ClientID: route.clientID,
		TransactionID: transactionID, ProviderGeneration: route.providerGeneration,
		RecoveryEpoch: route.recoveryEpoch, RedirectID: route.redirectID,
		ReturnRouteID: route.returnRouteID,
	}
	if !route.IsValid() || !binding.IsValid() {
		return Binding{}, ErrInvalidBinding
	}
	return binding, nil
}

// DeploymentID returns the exact Deployment owning this login route.
func (route Route) DeploymentID() deployment.ID { return route.deploymentID }

// ProviderID returns the exact configured provider identity.
func (route Route) ProviderID() ProviderID { return route.providerID }

// ClientID returns the exact configured provider-client identity.
func (route Route) ClientID() ClientID { return route.clientID }

// ProviderGeneration returns the trust generation fixed by this route.
func (route Route) ProviderGeneration() int64 { return route.providerGeneration }

// RecoveryEpoch returns the Deployment anti-rollback epoch fixed by this route.
func (route Route) RecoveryEpoch() int64 { return route.recoveryEpoch }

// DiscoveryURI returns the exact allowlisted metadata endpoint.
func (route Route) DiscoveryURI() string { return route.discoveryURI }

// Issuer returns the exact configured issuer.
func (route Route) Issuer() string { return route.issuer }

// AuthorizationEndpoint returns the exact allowlisted authorization endpoint.
func (route Route) AuthorizationEndpoint() string { return route.authorizationEndpoint }

// TokenEndpoint returns the exact allowlisted back-channel token endpoint.
func (route Route) TokenEndpoint() string { return route.tokenEndpoint }

// JWKSURI returns the exact configured signing-key endpoint.
func (route Route) JWKSURI() string { return route.jwksURI }

// OIDCClientID returns the exact external OIDC client identifier.
func (route Route) OIDCClientID() string { return route.oidcClientID }

// ConnectorID returns the optional broker connector fixed before redirect.
// An empty value identifies a direct OIDC provider route without a broker hop.
func (route Route) ConnectorID() string { return route.connectorID }

// ClientAuthMethod returns the exact configured token-endpoint authentication method.
func (route Route) ClientAuthMethod() string { return route.clientAuthMethod }

// Scopes returns a defensive copy of the exact requested OIDC scopes.
func (route Route) Scopes() []string { return slices.Clone(route.scopes) }

// AllowedAlgorithms returns a defensive copy of the accepted ID-token algorithms.
func (route Route) AllowedAlgorithms() []string {
	return slices.Clone(route.allowedAlgorithms)
}

// RedirectID returns the stable Core-owned callback registration identifier.
func (route Route) RedirectID() string { return route.redirectID }

// RedirectURI returns the exact registered callback URI.
func (route Route) RedirectURI() string { return route.redirectURI }

// ReturnRouteID returns the allowlisted local post-login route identifier.
func (route Route) ReturnRouteID() string { return route.returnRouteID }

// IsValid reports whether the immutable route still satisfies browser-login policy.
func (route Route) IsValid() bool {
	validated, err := NewRoute(RouteParams{
		DeploymentID: route.deploymentID,
		ProviderID:   route.providerID, ClientID: route.clientID,
		ProviderGeneration: route.providerGeneration, RecoveryEpoch: route.recoveryEpoch,
		Issuer: route.issuer, DiscoveryURI: route.discoveryURI,
		AuthorizationEndpoint: route.authorizationEndpoint, TokenEndpoint: route.tokenEndpoint,
		JWKSURI:      route.jwksURI,
		OIDCClientID: route.oidcClientID, ConnectorID: route.connectorID, ClientKind: "confidential",
		ClientAuthMethod: route.clientAuthMethod, Scopes: route.scopes,
		AllowedAlgorithms: route.allowedAlgorithms, RedirectID: route.redirectID,
		RedirectURI: route.redirectURI, ReturnRouteID: route.returnRouteID,
	})
	return err == nil && slices.Equal(validated.scopes, route.scopes) &&
		slices.Equal(validated.allowedAlgorithms, route.allowedAlgorithms)
}

func validConnectorBinding(connectorID string, scopes []string) bool {
	bound := connectorID != ""
	return bound == slices.Contains(scopes, "federated:id") && (!bound || validRouteID(connectorID))
}

func validClientAuthMethod(value string) bool {
	return value == "client_secret_basic" || value == "private_key_jwt"
}

func validScopes(values []string) bool {
	if len(values) == 0 || len(values) > maximumScopes || !slices.Contains(values, "openid") {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validBoundedToken(value, 128) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validAlgorithms(values []string) bool {
	if len(values) == 0 || len(values) > maximumAlgorithms {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "RS256" && value != "PS256" && value != "ES256" {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func validHTTPSURL(value string, allowIssuerPath bool) bool {
	if !validBoundedValue(value, maximumURLBytes) {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawPath != "" {
		return false
	}
	if !allowIssuerPath && parsed.Path == "" {
		return false
	}
	return parsed.String() == value
}

func validBoundedValue(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && strings.TrimSpace(value) == value
}

func validBoundedToken(value string, maximum int) bool {
	if !validBoundedValue(value, maximum) {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character >= 0x7f {
			return false
		}
	}
	return true
}

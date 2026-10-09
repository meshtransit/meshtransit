package oidcauth

import (
	"errors"
	"net/url"
	"testing"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/workspace"
)

func TestAuthorizationRequestBindsExactOIDCFlow(t *testing.T) {
	t.Parallel()

	route := routeFixture(t)
	metadata := metadataFixture(t)
	secrets := secretFixture(t)
	request, err := NewAuthorizationRequest(route, metadata, secrets)
	if err != nil {
		t.Fatalf("NewAuthorizationRequest() error = %v", err)
	}
	if !request.IsValid() {
		t.Fatal("NewAuthorizationRequest() returned invalid request")
	}
	location, err := url.Parse(request.Location())
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	query := location.Query()
	expected := map[string]string{
		"client_id":             "meshtransit-console",
		"code_challenge":        secrets.Verifier().Challenge(),
		"code_challenge_method": "S256",
		"nonce":                 secrets.Nonce().Encoded(),
		"redirect_uri":          "https://login.example.test/auth/callback",
		"response_mode":         "query",
		"response_type":         "code",
		"scope":                 "openid profile email",
		"state":                 secrets.State().Encoded(),
	}
	for name, expectedValue := range expected {
		if values := query[name]; len(values) != 1 || values[0] != expectedValue {
			t.Errorf("authorization parameter %q = %q, want %q", name, values, expectedValue)
		}
	}
	if len(query) != len(expected) {
		t.Fatalf("authorization parameter count = %d, want %d", len(query), len(expected))
	}
}

func TestAuthorizationRequestBindsExactBrokerConnector(t *testing.T) {
	t.Parallel()

	params := routeParamsFixture(t)
	params.ConnectorID = "google-v1"
	params.Scopes = append(params.Scopes, "federated:id")
	route, err := NewRoute(params)
	if err != nil {
		t.Fatalf("NewRoute() error = %v", err)
	}
	request, err := NewAuthorizationRequest(route, metadataFixture(t), secretFixture(t))
	if err != nil {
		t.Fatalf("NewAuthorizationRequest() error = %v", err)
	}
	location, err := url.Parse(request.Location())
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	query := location.Query()
	if len(query) != 10 || query.Get("connector_id") != params.ConnectorID ||
		query.Get("scope") != "openid profile email federated:id" {
		t.Fatal("authorization request did not bind the exact broker connector")
	}
}

func TestRouteRejectsUnpairedBrokerConnectorBinding(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		change func(*RouteParams)
	}{
		{name: "connector without claim scope", change: func(params *RouteParams) {
			params.ConnectorID = "google-v1"
		}},
		{name: "claim scope without connector", change: func(params *RouteParams) {
			params.Scopes = append(params.Scopes, "federated:id")
		}},
		{name: "invalid connector", change: func(params *RouteParams) {
			params.ConnectorID = "Google v1"
			params.Scopes = append(params.Scopes, "federated:id")
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := routeParamsFixture(t)
			test.change(&params)
			if _, err := NewRoute(params); !errors.Is(err, ErrInvalidRoute) {
				t.Fatalf("NewRoute() error = %v", err)
			}
		})
	}
}

func TestAuthorizationRequestSupportsExplicitCrossOriginEndpoints(t *testing.T) {
	t.Parallel()

	params := routeParamsFixture(t)
	params.DiscoveryURI = "https://metadata.example.test/.well-known/openid-configuration"
	params.AuthorizationEndpoint = "https://authorize.example.test/oauth2/authorize"
	params.TokenEndpoint = "https://tokens.example.test/oauth2/token"
	params.JWKSURI = "https://keys.example.test/oauth2/jwks"
	route, err := NewRoute(params)
	if err != nil {
		t.Fatalf("NewRoute() error = %v", err)
	}
	metadataParams := metadataParamsFixture()
	metadataParams.AuthorizationEndpoint = params.AuthorizationEndpoint
	metadataParams.TokenEndpoint = params.TokenEndpoint
	metadataParams.JWKSURI = params.JWKSURI
	metadata, err := NewMetadata(metadataParams)
	if err != nil {
		t.Fatalf("NewMetadata() error = %v", err)
	}
	request, err := NewAuthorizationRequest(route, metadata, secretFixture(t))
	if err != nil {
		t.Fatalf("NewAuthorizationRequest() error = %v", err)
	}
	location, err := url.Parse(request.Location())
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	if location.Scheme+"://"+location.Host != "https://authorize.example.test" {
		t.Fatalf("authorization origin = %q, want exact allowlisted origin", location.Scheme+"://"+location.Host)
	}
}

func TestAuthorizationRequestRejectsTrustSubstitution(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mutate   func(*MetadataParams)
		expected error
	}{
		{
			name: "issuer mismatch",
			mutate: func(params *MetadataParams) {
				params.Issuer = "https://other.example.test/realms/meshtransit"
				params.AuthorizationEndpoint = "https://other.example.test/oauth2/authorize"
				params.TokenEndpoint = "https://other.example.test/oauth2/token"
				params.JWKSURI = "https://other.example.test/oauth2/jwks"
			},
			expected: ErrProviderMismatch,
		},
		{
			name: "unsupported client authentication",
			mutate: func(params *MetadataParams) {
				params.TokenAuthMethods = []string{"private_key_jwt"}
			},
			expected: ErrUnsupportedProvider,
		},
		{
			name: "authorization endpoint drift",
			mutate: func(params *MetadataParams) {
				params.AuthorizationEndpoint = "https://authorize.example.test/oauth2/authorize"
			},
			expected: ErrProviderMismatch,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			params := metadataParamsFixture()
			test.mutate(&params)
			metadata, err := NewMetadata(params)
			if err != nil {
				t.Fatalf("NewMetadata() error = %v", err)
			}
			_, err = NewAuthorizationRequest(routeFixture(t), metadata, secretFixture(t))
			if !errors.Is(err, test.expected) {
				t.Fatalf("NewAuthorizationRequest() error = %v, want %v", err, test.expected)
			}
		})
	}
}

func TestRouteAndMetadataDefensivelyCopyCapabilities(t *testing.T) {
	t.Parallel()

	scopes := []string{"openid", "profile"}
	algorithms := []string{"RS256"}
	params := routeParamsFixture(t)
	params.Scopes = scopes
	params.AllowedAlgorithms = algorithms
	route, err := NewRoute(params)
	if err != nil {
		t.Fatalf("NewRoute() error = %v", err)
	}
	scopes[0] = "offline_access"
	algorithms[0] = "none"
	returnedScopes := route.Scopes()
	returnedAlgorithms := route.AllowedAlgorithms()
	returnedScopes[0] = "offline_access"
	returnedAlgorithms[0] = "none"
	if !route.IsValid() {
		t.Fatal("Route aliases caller-owned capability slices")
	}

	metadataParams := metadataParamsFixture()
	metadata, err := NewMetadata(metadataParams)
	if err != nil {
		t.Fatalf("NewMetadata() error = %v", err)
	}
	metadataParams.ResponseTypes[0] = "token"
	if !metadata.IsValid() {
		t.Fatal("Metadata aliases caller-owned capability slices")
	}
}

func routeFixture(t *testing.T) Route {
	t.Helper()
	route, err := NewRoute(routeParamsFixture(t))
	if err != nil {
		t.Fatalf("NewRoute() error = %v", err)
	}
	return route
}

func routeParamsFixture(t *testing.T) RouteParams {
	t.Helper()
	// #nosec G101 -- synthetic OIDC client metadata contains no credential material.
	return RouteParams{
		DeploymentID:       mustDeploymentID(t, "01890f00-0000-7000-8000-000000000001"),
		ProviderID:         mustProviderID(t, "01890f00-0000-7000-8000-000000000003"),
		ClientID:           mustClientID(t, "01890f00-0000-7000-8000-000000000004"),
		ProviderGeneration: 3, RecoveryEpoch: 7,
		Issuer:                "https://login.example.test/realms/meshtransit",
		DiscoveryURI:          "https://login.example.test/realms/meshtransit/.well-known/openid-configuration",
		AuthorizationEndpoint: "https://login.example.test/realms/meshtransit/protocol/openid-connect/auth",
		TokenEndpoint:         "https://login.example.test/realms/meshtransit/protocol/openid-connect/token",
		JWKSURI:               "https://login.example.test/realms/meshtransit/protocol/openid-connect/certs",
		OIDCClientID:          "meshtransit-console", ClientKind: "confidential",
		ClientAuthMethod:  "client_secret_basic",
		Scopes:            []string{"openid", "profile", "email"},
		AllowedAlgorithms: []string{"RS256", "PS256"},
		RedirectID:        "console.callback.v1",
		RedirectURI:       "https://login.example.test/auth/callback",
		ReturnRouteID:     "workspace.home",
	}
}

func metadataFixture(t *testing.T) Metadata {
	t.Helper()
	metadata, err := NewMetadata(metadataParamsFixture())
	if err != nil {
		t.Fatalf("NewMetadata() error = %v", err)
	}
	return metadata
}

func metadataParamsFixture() MetadataParams {
	// #nosec G101 -- synthetic provider capability metadata contains no credential material.
	return MetadataParams{
		Issuer:                "https://login.example.test/realms/meshtransit",
		AuthorizationEndpoint: "https://login.example.test/realms/meshtransit/protocol/openid-connect/auth",
		TokenEndpoint:         "https://login.example.test/realms/meshtransit/protocol/openid-connect/token",
		JWKSURI:               "https://login.example.test/realms/meshtransit/protocol/openid-connect/certs",
		ResponseTypes:         []string{"code"}, CodeChallengeMethods: []string{"S256"},
		IDTokenSigningAlgorithms: []string{"RS256", "PS256"},
		TokenAuthMethods:         []string{"client_secret_basic", "private_key_jwt"},
	}
}

func mustDeploymentID(t *testing.T, value string) deployment.ID {
	t.Helper()
	id, err := deployment.ParseID(value)
	if err != nil {
		t.Fatalf("deployment.ParseID() error = %v", err)
	}
	return id
}

func mustWorkspaceID(t *testing.T, value string) workspace.ID {
	t.Helper()
	id, err := workspace.ParseID(value)
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	return id
}

func mustProviderID(t *testing.T, value string) ProviderID {
	t.Helper()
	id, err := ParseProviderID(value)
	if err != nil {
		t.Fatalf("ParseProviderID() error = %v", err)
	}
	return id
}

func mustClientID(t *testing.T, value string) ClientID {
	t.Helper()
	id, err := ParseClientID(value)
	if err != nil {
		t.Fatalf("ParseClientID() error = %v", err)
	}
	return id
}

func mustTransactionID(t *testing.T, value string) TransactionID {
	t.Helper()
	id, err := ParseTransactionID(value)
	if err != nil {
		t.Fatalf("ParseTransactionID() error = %v", err)
	}
	return id
}

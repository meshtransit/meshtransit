package oidc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const validDiscoveryBody = `{
  "issuer":"https://login.example.test/realms/meshtransit",
  "authorization_endpoint":"https://login.example.test/realms/meshtransit/protocol/openid-connect/auth",
  "token_endpoint":"https://login.example.test/realms/meshtransit/protocol/openid-connect/token",
  "jwks_uri":"https://login.example.test/realms/meshtransit/protocol/openid-connect/certs",
  "response_types_supported":["code"],
  "code_challenge_methods_supported":["S256"],
  "id_token_signing_alg_values_supported":["RS256","PS256"],
  "token_endpoint_auth_methods_supported":["client_secret_basic"],
  "ignored_extension":{"safe":true}
}`

func TestResolverCloseOnlyReleasesOwnedIdleConnections(t *testing.T) {
	t.Parallel()
	var absent *Resolver
	absent.Close()
	transport := &discoveryIdleCloseTransport{}
	resolver := &Resolver{client: &http.Client{Transport: transport}}
	resolver.Close()
	resolver.Close()
	if transport.closes != 2 || transport.requests != 0 {
		t.Fatal("idle cleanup performed request work or did not delegate")
	}
	resolver = &Resolver{client: doerFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("cleanup invoked a borrowed test client")
		return nil, ErrDiscoveryUnavailable
	})}
	resolver.Close()
}

type discoveryIdleCloseTransport struct{ closes, requests int }

func (transport *discoveryIdleCloseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.requests++
	return nil, ErrDiscoveryUnavailable
}

func (transport *discoveryIdleCloseTransport) CloseIdleConnections() { transport.closes++ }

func TestResolverReturnsExactValidatedMetadata(t *testing.T) {
	t.Parallel()

	client := doerFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != discoveryRoute(t).DiscoveryURI() {
			t.Fatalf("request = %s %s, want exact discovery GET", request.Method, request.URL)
		}
		if request.Header.Get("Accept") != "application/json" || request.Header.Get("User-Agent") == "" {
			t.Fatal("discovery request omitted bounded protocol headers")
		}
		return discoveryResponse(http.StatusOK, "application/json; charset=utf-8", validDiscoveryBody), nil
	})
	resolver, err := newResolver(client, 64*1024)
	if err != nil {
		t.Fatalf("newResolver() error = %v", err)
	}
	metadata, err := resolver.Resolve(t.Context(), discoveryRoute(t))
	if err != nil {
		t.Fatalf("Resolver.Resolve() error = %v", err)
	}
	if !metadata.IsValid() || metadata.Issuer() != discoveryRoute(t).Issuer() ||
		metadata.JWKSURI() != discoveryRoute(t).JWKSURI() {
		t.Fatal("Resolver.Resolve() widened configured trust")
	}
}

func TestResolverRejectsUntrustedResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		maximum     int64
	}{
		{
			name: "redirect", status: http.StatusFound,
			contentType: "application/json", body: validDiscoveryBody, maximum: 64 * 1024,
		},
		{
			name: "non-json", status: http.StatusOK,
			contentType: "text/html", body: validDiscoveryBody, maximum: 64 * 1024,
		},
		{
			name: "duplicate issuer", status: http.StatusOK,
			contentType: "application/json",
			body: strings.Replace(
				validDiscoveryBody,
				`"issuer":"https://login.example.test/realms/meshtransit",`,
				`"issuer":"https://login.example.test/realms/meshtransit","issuer":"https://evil.example.test",`,
				1,
			),
			maximum: 64 * 1024,
		},
		{
			name: "issuer substitution", status: http.StatusOK,
			contentType: "application/json",
			body: strings.Replace(
				validDiscoveryBody,
				"https://login.example.test/realms/meshtransit",
				"https://evil.example.test/realms/meshtransit",
				1,
			),
			maximum: 64 * 1024,
		},
		{
			name: "authorization endpoint drift", status: http.StatusOK,
			contentType: "application/json",
			body: strings.Replace(
				validDiscoveryBody,
				"https://login.example.test/realms/meshtransit/protocol/openid-connect/auth",
				"https://authorize.example.test/oauth2/authorize",
				1,
			),
			maximum: 64 * 1024,
		},
		{
			name: "oversized", status: http.StatusOK,
			contentType: "application/json", body: validDiscoveryBody, maximum: 64,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := doerFunc(func(*http.Request) (*http.Response, error) {
				return discoveryResponse(test.status, test.contentType, test.body), nil
			})
			resolver, err := newResolver(client, test.maximum)
			if err != nil {
				t.Fatalf("newResolver() error = %v", err)
			}
			_, err = resolver.Resolve(t.Context(), discoveryRoute(t))
			if !errors.Is(err, ErrInvalidDiscoveryResponse) {
				t.Fatalf("Resolver.Resolve() error = %v, want ErrInvalidDiscoveryResponse", err)
			}
		})
	}
}

func TestResolverClassifiesTransportFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("provider unavailable")
	resolver, err := newResolver(doerFunc(func(*http.Request) (*http.Response, error) {
		return nil, wantErr
	}), 64*1024)
	if err != nil {
		t.Fatalf("newResolver() error = %v", err)
	}
	_, err = resolver.Resolve(t.Context(), discoveryRoute(t))
	if !errors.Is(err, ErrDiscoveryUnavailable) || !errors.Is(err, wantErr) {
		t.Fatalf("Resolver.Resolve() error = %v, want classified transport failure", err)
	}
}

func TestResolverHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	resolver, err := newResolver(doerFunc(func(request *http.Request) (*http.Response, error) {
		return nil, request.Context().Err()
	}), 64*1024)
	if err != nil {
		t.Fatalf("newResolver() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = resolver.Resolve(ctx, discoveryRoute(t))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Resolver.Resolve() error = %v, want context.Canceled", err)
	}
}

type doerFunc func(*http.Request) (*http.Response, error)

func (function doerFunc) Do(request *http.Request) (*http.Response, error) {
	return function(request)
}

func discoveryResponse(status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func discoveryRoute(t testing.TB) oidcauth.Route {
	t.Helper()
	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("deployment.ParseID() error = %v", err)
	}
	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000002")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	providerID, err := oidcauth.ParseProviderID("01890f00-0000-7000-8000-000000000003")
	if err != nil {
		t.Fatalf("oidcauth.ParseProviderID() error = %v", err)
	}
	clientID, err := oidcauth.ParseClientID("01890f00-0000-7000-8000-000000000004")
	if err != nil {
		t.Fatalf("oidcauth.ParseClientID() error = %v", err)
	}
	// #nosec G101 -- synthetic OIDC client metadata contains no credential material.
	route, err := oidcauth.NewRoute(oidcauth.RouteParams{
		DeploymentID: deploymentID, WorkspaceID: workspaceID,
		ProviderID: providerID, ClientID: clientID,
		ProviderGeneration: 3, RecoveryEpoch: 7,
		Issuer:                "https://login.example.test/realms/meshtransit",
		DiscoveryURI:          "https://login.example.test/realms/meshtransit/.well-known/openid-configuration",
		AuthorizationEndpoint: "https://login.example.test/realms/meshtransit/protocol/openid-connect/auth",
		TokenEndpoint:         "https://login.example.test/realms/meshtransit/protocol/openid-connect/token",
		JWKSURI:               "https://login.example.test/realms/meshtransit/protocol/openid-connect/certs",
		OIDCClientID:          "meshtransit-console", ClientKind: "confidential",
		ClientAuthMethod: "client_secret_basic", Scopes: []string{"openid"},
		AllowedAlgorithms: []string{"RS256"}, RedirectID: "console.callback.v1",
		RedirectURI:   "https://login.example.test/auth/callback",
		ReturnRouteID: "workspace.home",
	})
	if err != nil {
		t.Fatalf("oidcauth.NewRoute() error = %v", err)
	}
	return route
}

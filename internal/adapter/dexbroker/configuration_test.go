//go:build dexbroker

package dexbroker

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	dexoidc "github.com/dexidp/dex/connector/oidc"
	"github.com/dexidp/dex/storage"
	"github.com/dexidp/dex/storage/memory"
)

func TestConfigurationFingerprintIsStableAndBindsTrustInputs(t *testing.T) {
	options := validServiceTestOptions(t)
	first, err := CalculateConfigurationFingerprint(options)
	if err != nil {
		t.Fatalf("first fingerprint: %v", err)
	}
	second, err := CalculateConfigurationFingerprint(options)
	if err != nil {
		t.Fatalf("second fingerprint: %v", err)
	}
	if first != second || !strings.HasPrefix(first, configurationFingerprintPrefix) {
		t.Fatalf("fingerprints = (%q, %q)", first, second)
	}
	options.OIDCConnectors[0].Generation++
	changed, err := CalculateConfigurationFingerprint(options)
	if err != nil {
		t.Fatalf("changed fingerprint: %v", err)
	}
	if changed == first {
		t.Fatal("connector generation did not change fingerprint")
	}
	options = validServiceTestOptions(t)
	options.OIDCConnectors[0].Endpoints.TokenURL = "https://oauth2.googleapis.com/token-v2"
	changed, err = CalculateConfigurationFingerprint(options)
	if err != nil {
		t.Fatalf("endpoint fingerprint: %v", err)
	}
	if changed == first {
		t.Fatal("provider endpoint policy did not change fingerprint")
	}
}

func TestConfigurationRejectsProviderEndpointWithExplicitPort(t *testing.T) {
	options := validServiceTestOptions(t)
	options.OIDCConnectors[0].Endpoints.TokenURL = "https://oauth2.googleapis.com:443/token"
	if _, err := CalculateConfigurationFingerprint(options); !errors.Is(err, errInvalidConfiguration) {
		t.Fatalf("CalculateConfigurationFingerprint() error = %v", err)
	}
}

func TestImmutableConfigurationMapsExactOIDCPolicyAndHidesDynamicRecords(t *testing.T) {
	base := memory.New(componentTestLogger())
	if err := base.CreateConnector(t.Context(), storage.Connector{
		ID: "dynamic", Type: "mockCallback", Name: "Dynamic",
	}); err != nil {
		t.Fatalf("create dynamic connector: %v", err)
	}
	if err := base.CreateClient(t.Context(), storage.Client{
		ID: "dynamic-client", Secret: "dynamic-secret", Name: "Dynamic Client",
	}); err != nil {
		t.Fatalf("create dynamic client: %v", err)
	}
	configuration := componentConfiguration{
		connectors: []componentOIDCConnector{{
			id: "google-v1", displayName: "Google", generation: 7,
			issuer:       "https://accounts.google.com",
			endpoints:    GoogleOIDCProviderEndpoints(),
			clientID:     "google-client.apps.googleusercontent.com",
			clientSecret: strings.Repeat("c", 48),
		}},
		clients: []componentClient{{
			id: "meshtransit-core", displayName: "MeshTransit Core", generation: 9,
			secret: strings.Repeat("b", 48), redirectURI: "https://app.example.test/auth/callback",
		}},
	}
	configured, err := withImmutableConfiguration(base, "https://id.example.test/oauth2", configuration)
	if err != nil {
		t.Fatalf("withImmutableConfiguration() error = %v", err)
	}
	connectors, err := configured.ListConnectors(t.Context())
	if err != nil || len(connectors) != 1 || connectors[0].ID != "google-v1" ||
		connectors[0].ResourceVersion != "7" || connectors[0].Type != oidcConnectorType {
		t.Fatal("configured connector contract mismatch")
	}
	var oidcConfig dexoidc.Config
	if err := json.Unmarshal(connectors[0].Config, &oidcConfig); err != nil {
		t.Fatalf("decode connector: %v", err)
	}
	if oidcConfig.Issuer != "https://accounts.google.com" ||
		oidcConfig.RedirectURI != "https://id.example.test/oauth2/callback" ||
		oidcConfig.ProviderDiscoveryOverrides.AuthURL != googleAuthorizationURL ||
		oidcConfig.ProviderDiscoveryOverrides.TokenURL != googleTokenURL ||
		oidcConfig.ProviderDiscoveryOverrides.JWKSURL != googleJWKSURL ||
		oidcConfig.PKCEChallenge != pkceS256 ||
		!slices.Equal(oidcConfig.Scopes, []string{"profile", "email"}) ||
		oidcConfig.InsecureSkipVerify || oidcConfig.InsecureSkipEmailVerified || oidcConfig.InsecureEnableGroups {
		t.Fatal("OIDC connector policy mismatch")
	}
	clients, err := configured.ListClients(t.Context())
	if err != nil || len(clients) != 1 || clients[0].ID != "meshtransit-core" ||
		clients[0].Public || len(clients[0].TrustedPeers) != 0 ||
		!slices.Equal(clients[0].RedirectURIs, []string{"https://app.example.test/auth/callback"}) {
		t.Fatal("configured client contract mismatch")
	}
	if _, err := configured.GetConnector(t.Context(), "dynamic"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("dynamic connector lookup error = %v", err)
	}
	if _, err := configured.GetClient(t.Context(), "dynamic-client"); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("dynamic client lookup error = %v", err)
	}
	if err := configured.CreateConnector(context.Background(), storage.Connector{}); !errors.Is(err, errImmutableConfiguration) {
		t.Fatalf("CreateConnector() error = %v", err)
	}
	if err := configured.CreateClient(context.Background(), storage.Client{}); !errors.Is(err, errImmutableConfiguration) {
		t.Fatalf("CreateClient() error = %v", err)
	}
	baseConnectors, err := base.ListConnectors(t.Context())
	if err != nil || len(baseConnectors) != 1 || baseConnectors[0].ID != "dynamic" {
		t.Fatal("static connector was persisted to backing storage")
	}
	baseClients, err := base.ListClients(t.Context())
	if err != nil || len(baseClients) != 1 || baseClients[0].ID != "dynamic-client" {
		t.Fatal("static client was persisted to backing storage")
	}
}

//go:build dexbroker

package dexbroker

import (
	"errors"
	"slices"
	"testing"
)

func TestCompareDiscoveryReportsEveryPinnedMismatch(t *testing.T) {
	issuer := "https://sso.example.test:8443/realms/corp"
	connector := OIDCConnectorOptions{Issuer: issuer, Endpoints: genericTestEndpoints(issuer)}
	connector.Endpoints.UserInfoURL = issuer + "/protocol/openid-connect/userinfo"
	matching := discoveryDocument{
		Issuer: issuer, AuthorizationEndpoint: connector.Endpoints.AuthorizationURL,
		TokenEndpoint: connector.Endpoints.TokenURL, JWKSURI: connector.Endpoints.JWKSURL,
		UserInfoEndpoint: connector.Endpoints.UserInfoURL,
	}
	if findings := compareDiscovery(connector, matching); len(findings) != 0 {
		t.Fatalf("matching document findings = %+v", findings)
	}
	drifted := matching
	drifted.Issuer += "/"
	drifted.UserInfoEndpoint = "https://other.example.test/userinfo"
	findings := compareDiscovery(connector, drifted)
	fields := make([]string, 0, len(findings))
	for _, finding := range findings {
		fields = append(fields, finding.Field)
	}
	if !slices.Equal(fields, []string{"issuer", "userinfo_url"}) {
		t.Fatalf("findings = %+v", findings)
	}
	// Without a pinned userinfo URL the discovered one is not compared.
	connector.Endpoints.UserInfoURL = ""
	if findings := compareDiscovery(connector, drifted); len(findings) != 1 {
		t.Fatalf("unpinned userinfo findings = %+v", findings)
	}
}

func TestCheckProviderDiscoveryRefusesInvalidConnector(t *testing.T) {
	issuer := "https://sso.example.test:8443/realms/corp"
	connector := OIDCConnectorOptions{Issuer: issuer, Endpoints: genericTestEndpoints(issuer), Prompt: "consent"}
	if _, err := CheckProviderDiscovery(t.Context(), connector); !errors.Is(err, errInvalidConfiguration) {
		t.Fatalf("CheckProviderDiscovery() error = %v", err)
	}
}

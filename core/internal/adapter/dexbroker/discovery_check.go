//go:build dexbroker

package dexbroker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
)

// errDiscoveryUnavailable reports a discovery document that could not be
// read or parsed through the connector's outbound policy.
var errDiscoveryUnavailable = errors.New("dex broker provider discovery unavailable")

// DiscoveryFinding is a pinned value the provider's discovery document
// disagrees with. URLs are public provider metadata, never secrets.
type DiscoveryFinding struct {
	Field      string `json:"field"`
	Pinned     string `json:"pinned"`
	Discovered string `json:"discovered"`
}

type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
}

// CheckProviderDiscovery reads the connector's discovery document once,
// through the same outbound policy the broker uses (setup check, V1-22), and
// reports every pinned value it disagrees with. It changes nothing: the
// operator fixes the configuration. Dex reads discovery again whenever it
// opens the connector and calls the discovered userinfo endpoint, so a
// pinned userinfo URL that differs from it would fail every sign-in.
func CheckProviderDiscovery(ctx context.Context, connector OIDCConnectorOptions) ([]DiscoveryFinding, error) {
	if !validConnectorIssuer(connector.Issuer) || !validProviderEndpoints(connector.Issuer, connector.Endpoints) ||
		!validConnectorOptions(connector) {
		return nil, errInvalidConfiguration
	}
	var caPEM []byte
	if connector.CAFile.IsSet() {
		contents, err := connector.CAFile.Read()
		if err != nil || len(contents) > maximumConnectorCABytes || !validCAPEM(contents) {
			return nil, errInvalidConfiguration
		}
		caPEM = contents
	}
	client, transport, err := newOIDCOutboundHTTPClient(connector.Endpoints,
		outboundConnectorPolicy{caPEM: caPEM, privateNetworks: connector.PrivateNetworks})
	if err != nil {
		return nil, err
	}
	defer transport.CloseIdleConnections()
	document, err := fetchDiscovery(ctx, client, connector.Endpoints.DiscoveryURL)
	if err != nil {
		return nil, err
	}
	return compareDiscovery(connector, document), nil
}

func fetchDiscovery(ctx context.Context, client *http.Client, discoveryURL string) (discoveryDocument, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return discoveryDocument{}, errDiscoveryUnavailable
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return discoveryDocument{}, errors.Join(errDiscoveryUnavailable, err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, response.Body)
		return discoveryDocument{}, errDiscoveryUnavailable
	}
	var document discoveryDocument
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return discoveryDocument{}, errDiscoveryUnavailable
	}
	return document, nil
}

func compareDiscovery(connector OIDCConnectorOptions, document discoveryDocument) []DiscoveryFinding {
	endpoints := connector.Endpoints
	pairs := []DiscoveryFinding{
		// go-oidc compares the issuer byte for byte, trailing "/" included.
		{Field: "issuer", Pinned: connector.Issuer, Discovered: document.Issuer},
		{Field: "authorization_url", Pinned: endpoints.AuthorizationURL, Discovered: document.AuthorizationEndpoint},
		{Field: "token_url", Pinned: endpoints.TokenURL, Discovered: document.TokenEndpoint},
		{Field: "jwks_url", Pinned: endpoints.JWKSURL, Discovered: document.JWKSURI},
	}
	if endpoints.UserInfoURL != "" {
		pairs = append(pairs, DiscoveryFinding{
			Field: "userinfo_url", Pinned: endpoints.UserInfoURL, Discovered: document.UserInfoEndpoint,
		})
	}
	findings := make([]DiscoveryFinding, 0, len(pairs))
	for _, pair := range pairs {
		if pair.Pinned != pair.Discovered {
			findings = append(findings, pair)
		}
	}
	return findings
}

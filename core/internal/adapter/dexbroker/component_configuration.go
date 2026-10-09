//go:build dexbroker

package dexbroker

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"

	dexoidc "github.com/dexidp/dex/connector/oidc"
	"github.com/dexidp/dex/storage"
)

const (
	oidcConnectorType = "oidc"
	pkceS256          = "S256"
	// upstreamAccountPrompt asks the upstream provider to show its account
	// chooser on every sign-in. Without it Google reuses the browser's
	// signed-in account, so signing out of MeshTransit never lets a person
	// pick another account. Dex sends prompt only with offline_access, which
	// MeshTransit never requests, so the broker adds it to the authorization
	// URL itself.
	upstreamAccountPrompt = "select_account"
)

var errImmutableConfiguration = errors.New("immutable broker configuration")

type immutableConfigurationStorage struct {
	storage.Storage
	clients        []storage.Client
	clientsByID    map[string]storage.Client
	connectors     []storage.Connector
	connectorsByID map[string]storage.Connector
}

func withImmutableConfiguration(
	serverStorage storage.Storage,
	brokerIssuer string,
	configuration componentConfiguration,
) (storage.Storage, error) {
	if len(configuration.connectors) == 0 && len(configuration.clients) == 0 {
		return serverStorage, nil
	}
	if len(configuration.connectors) == 0 || len(configuration.clients) == 0 {
		return nil, errImmutableConfiguration
	}
	wrapped := &immutableConfigurationStorage{
		Storage:        serverStorage,
		clients:        make([]storage.Client, 0, len(configuration.clients)),
		clientsByID:    make(map[string]storage.Client, len(configuration.clients)),
		connectors:     make([]storage.Connector, 0, len(configuration.connectors)),
		connectorsByID: make(map[string]storage.Connector, len(configuration.connectors)),
	}
	for _, client := range configuration.clients {
		value := storage.Client{
			ID: client.id, Secret: client.secret, RedirectURIs: []string{client.redirectURI},
			TrustedPeers: []string{}, Public: false, Name: client.displayName,
		}
		if _, exists := wrapped.clientsByID[value.ID]; exists {
			return nil, errImmutableConfiguration
		}
		wrapped.clients = append(wrapped.clients, value)
		wrapped.clientsByID[value.ID] = value
	}
	for _, connector := range configuration.connectors {
		authorizationURL, err := withAccountPrompt(connector.endpoints.AuthorizationURL)
		if err != nil {
			return nil, errImmutableConfiguration
		}
		encoded, err := json.Marshal(dexoidc.Config{ //nolint:gosec // Required transient Dex connector input; immutable storage never persists it.
			Issuer: connector.issuer, ClientID: connector.clientID,
			ClientSecret: connector.clientSecret,
			RedirectURI:  brokerIssuer + "/callback",
			Scopes:       []string{"profile", "email"}, PKCEChallenge: pkceS256,
			ProviderDiscoveryOverrides: dexoidc.ProviderDiscoveryOverrides{
				AuthURL:  authorizationURL,
				TokenURL: connector.endpoints.TokenURL,
				JWKSURL:  connector.endpoints.JWKSURL,
			},
		})
		if err != nil {
			return nil, errImmutableConfiguration
		}
		value := storage.Connector{
			ID: connector.id, Type: oidcConnectorType, Name: connector.displayName,
			ResourceVersion: configurationGeneration(connector.generation), Config: encoded,
		}
		if _, exists := wrapped.connectorsByID[value.ID]; exists {
			return nil, errImmutableConfiguration
		}
		wrapped.connectors = append(wrapped.connectors, value)
		wrapped.connectorsByID[value.ID] = value
	}
	return wrapped, nil
}

// withAccountPrompt returns the authorization URL with the account chooser
// prompt. Any prompt already present is replaced, never combined.
func withAccountPrompt(authorizationURL string) (string, error) {
	parsed, err := url.Parse(authorizationURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Fragment != "" {
		return "", errImmutableConfiguration
	}
	query := parsed.Query()
	query.Set("prompt", upstreamAccountPrompt)
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func (configured *immutableConfigurationStorage) GetClient(
	_ context.Context,
	id string,
) (storage.Client, error) {
	client, exists := configured.clientsByID[id]
	if !exists {
		return storage.Client{}, storage.ErrNotFound
	}
	return cloneConfiguredClient(client), nil
}

func (configured *immutableConfigurationStorage) ListClients(context.Context) ([]storage.Client, error) {
	clients := make([]storage.Client, 0, len(configured.clients))
	for _, client := range configured.clients {
		clients = append(clients, cloneConfiguredClient(client))
	}
	return clients, nil
}

func (configured *immutableConfigurationStorage) CreateClient(context.Context, storage.Client) error {
	return errImmutableConfiguration
}

func (configured *immutableConfigurationStorage) UpdateClient(
	context.Context,
	string,
	func(storage.Client) (storage.Client, error),
) error {
	return errImmutableConfiguration
}

func (configured *immutableConfigurationStorage) DeleteClient(context.Context, string) error {
	return errImmutableConfiguration
}

func (configured *immutableConfigurationStorage) GetConnector(
	_ context.Context,
	id string,
) (storage.Connector, error) {
	connector, exists := configured.connectorsByID[id]
	if !exists {
		return storage.Connector{}, storage.ErrNotFound
	}
	return cloneConfiguredConnector(connector), nil
}

func (configured *immutableConfigurationStorage) ListConnectors(context.Context) ([]storage.Connector, error) {
	connectors := make([]storage.Connector, 0, len(configured.connectors))
	for _, connector := range configured.connectors {
		connectors = append(connectors, cloneConfiguredConnector(connector))
	}
	return connectors, nil
}

func (configured *immutableConfigurationStorage) CreateConnector(context.Context, storage.Connector) error {
	return errImmutableConfiguration
}

func (configured *immutableConfigurationStorage) UpdateConnector(
	context.Context,
	string,
	func(storage.Connector) (storage.Connector, error),
) error {
	return errImmutableConfiguration
}

func (configured *immutableConfigurationStorage) DeleteConnector(context.Context, string) error {
	return errImmutableConfiguration
}

func cloneConfiguredClient(client storage.Client) storage.Client {
	client.RedirectURIs = slices.Clone(client.RedirectURIs)
	client.TrustedPeers = slices.Clone(client.TrustedPeers)
	return client
}

func cloneConfiguredConnector(connector storage.Connector) storage.Connector {
	connector.Config = slices.Clone(connector.Config)
	return connector
}

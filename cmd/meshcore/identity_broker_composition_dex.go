//go:build dexbroker

package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/meshtransit/meshtransit/internal/adapter/dexbroker"
	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	"github.com/meshtransit/meshtransit/internal/app"
	"github.com/meshtransit/meshtransit/internal/config"
)

type identityPostgreSQLChecker struct {
	resource *dexbroker.PostgreSQLResource
}

type identityConfigurationChecker struct {
	service *dexbroker.Service
}

type identitySignerChecker struct {
	service *dexbroker.Service
}

func (checker *identityConfigurationChecker) Component() app.Component {
	return app.ComponentIdentityConfiguration
}

func (checker *identityConfigurationChecker) Check(ctx context.Context) error {
	if checker == nil || checker.service == nil {
		return errInvalidIdentityBrokerComposition
	}
	return checker.service.CheckConfiguration(ctx)
}

func (checker *identitySignerChecker) Component() app.Component {
	return app.ComponentIdentitySigner
}

func (checker *identitySignerChecker) Check(ctx context.Context) error {
	if checker == nil || checker.service == nil || ctx == nil || ctx.Err() != nil {
		return errInvalidIdentityBrokerComposition
	}
	// The dependency monitor runs its first check before services start. The
	// broker performs the same cryptographic proof synchronously during Start;
	// later checks exercise the running signer directly.
	if checker.service.Done() == nil {
		return nil
	}
	return checker.service.CheckSigner(ctx)
}

func (checker *identityPostgreSQLChecker) Component() app.Component {
	return app.ComponentIdentityPostgreSQL
}

func (checker *identityPostgreSQLChecker) Check(ctx context.Context) error {
	if checker == nil || checker.resource == nil {
		return errInvalidIdentityBrokerComposition
	}
	return checker.resource.Check(ctx)
}

func composeIdentityBroker(
	ctx context.Context,
	identity config.IdentityConfig,
	resources *resourceOwner,
	logger *slog.Logger,
) (identityBrokerComposition, error) {
	if ctx == nil || ctx.Err() != nil || resources == nil || logger == nil {
		return identityBrokerComposition{}, errInvalidIdentityBrokerComposition
	}
	resource, err := dexbroker.OpenPostgreSQLResource(
		ctx,
		identityPostgreSQLResourceOptions(identity.PostgreSQL),
		logger,
	)
	if err != nil {
		return identityBrokerComposition{}, errors.Join(errInvalidIdentityBrokerComposition, err)
	}
	if err := resources.Add("identity-postgresql", resource.Shutdown); err != nil {
		return identityBrokerComposition{}, errors.Join(
			errInvalidIdentityBrokerComposition,
			err,
			resource.Shutdown(ctx),
		)
	}
	service, err := dexbroker.NewService(identityServiceOptions(identity), resource, logger)
	if err != nil {
		return identityBrokerComposition{}, errors.Join(errInvalidIdentityBrokerComposition, err)
	}
	listener, err := composeIdentityListener(identity, service)
	if err != nil {
		return identityBrokerComposition{}, errors.Join(errInvalidIdentityBrokerComposition, err)
	}
	return identityBrokerComposition{
		checkers: []app.DependencyChecker{
			&identityPostgreSQLChecker{resource: resource},
			&identityConfigurationChecker{service: service},
			&identitySignerChecker{service: service},
		},
		services: []app.OwnedService{
			{Name: "identity-broker", Service: service},
			{Name: "identity-listener", Service: listener},
		},
	}, nil
}

func composeIdentityListener(
	identity config.IdentityConfig,
	service *dexbroker.Service,
) (*httpapi.IdentityServer, error) {
	certificatePEM, err := identity.Listener.TLSCertificateFile.Read()
	if err != nil {
		return nil, errInvalidIdentityBrokerComposition
	}
	defer clear(certificatePEM)
	privateKeyPEM, err := identity.Listener.TLSPrivateKeyFile.Read()
	if err != nil {
		return nil, errInvalidIdentityBrokerComposition
	}
	defer clear(privateKeyPEM)
	connectorIDs := make([]string, 0, len(identity.OIDCConnectors))
	for _, connector := range identity.OIDCConnectors {
		connectorIDs = append(connectorIDs, connector.ID)
	}
	listener, err := httpapi.NewIdentityServer(httpapi.IdentityServerOptions{
		Address: identity.Listener.Address, Issuer: identity.Issuer,
		CertificatePEM: certificatePEM, PrivateKeyPEM: privateKeyPEM,
		Handler: service, ConnectorIDs: connectorIDs,
		RequestTimeout:        identity.Listener.RequestTimeout,
		MaxConnections:        identity.Listener.MaxConnections,
		MaxConcurrentRequests: identity.Listener.MaxConcurrentRequests,
	})
	if err != nil {
		return nil, errInvalidIdentityBrokerComposition
	}
	return listener, nil
}

func identityPostgreSQLResourceOptions(
	postgres config.IdentityPostgreSQLConfig,
) dexbroker.PostgreSQLResourceOptions {
	return dexbroker.PostgreSQLResourceOptions{
		Address:               postgres.Address,
		Database:              postgres.Database,
		User:                  postgres.RuntimeUser,
		PasswordFile:          postgres.RuntimePasswordFile,
		CAFile:                postgres.CAFile,
		MaxOpenConnections:    postgres.MaxOpenConnections,
		MaxIdleConnections:    postgres.MaxIdleConnections,
		ConnectTimeout:        postgres.ConnectTimeout,
		MaxConnectionLifetime: postgres.MaxConnectionLifetime,
	}
}

func identityServiceOptions(identity config.IdentityConfig) dexbroker.ServiceOptions {
	connectors := make([]dexbroker.OIDCConnectorOptions, 0, len(identity.OIDCConnectors))
	for _, connector := range identity.OIDCConnectors {
		connectors = append(connectors, dexbroker.OIDCConnectorOptions{
			ID: connector.ID, DisplayName: connector.DisplayName, Generation: connector.Generation,
			Issuer: connector.Issuer, Endpoints: dexbroker.GoogleOIDCProviderEndpoints(),
			ClientID:         connector.ClientID,
			ClientSecretFile: connector.ClientSecretFile,
		})
	}
	clients := make([]dexbroker.ClientOptions, 0, len(identity.Clients))
	for _, client := range identity.Clients {
		clients = append(clients, dexbroker.ClientOptions{
			ID: client.ID, DisplayName: client.DisplayName, Generation: client.Generation,
			SecretFile: client.SecretFile, RedirectURI: client.RedirectURI,
		})
	}
	return dexbroker.ServiceOptions{
		Issuer:                    identity.Issuer,
		OIDCConnectors:            connectors,
		Clients:                   clients,
		ExpectedFingerprint:       dexbroker.ConfigurationFingerprint(identity.ExpectedFingerprint),
		IDTokenLifetime:           identity.IDTokenLifetime,
		AuthRequestLifetime:       identity.AuthRequestLifetime,
		SigningKeyRotation:        identity.SigningKeyRotation,
		GarbageCollectionInterval: identity.GarbageCollectionInterval,
	}
}

var _ app.Service = (*httpapi.IdentityServer)(nil)

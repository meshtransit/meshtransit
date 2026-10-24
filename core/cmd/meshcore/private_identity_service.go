package main

import (
	"log/slog"

	"meshtransit.net/core/internal/adapter/httpapi"
	"meshtransit.net/core/internal/platform/app"
)

type privateIdentityLoginServiceOptions struct {
	Address        string
	CertificatePEM []byte
	PrivateKeyPEM  []byte
	MaxConnections int
	Logger         *slog.Logger
}

// composePrivateIdentityLoginService serves only this concrete factory's graph.
// It opens nothing, accepts no alternate handler and does not enable public SSO.
// The process owner must shutdown/join before factory.Close or storage cleanup.
func composePrivateIdentityLoginService(
	factory *privateIdentityFactory,
	options privateIdentityLoginServiceOptions,
) (*httpapi.LoginServer, error) {
	if factory == nil || factory.identity == nil || factory.discovery == nil || factory.provider == nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	service, err := httpapi.NewLoginServer(httpapi.LoginServerOptions{
		Address: options.Address, CertificatePEM: options.CertificatePEM, PrivateKeyPEM: options.PrivateKeyPEM,
		Dispatcher: factory.identity.dispatcher, MaxConnections: options.MaxConnections, Logger: options.Logger,
	})
	if err != nil {
		return nil, errInvalidPrivateIdentityComposition
	}
	return service, nil
}

var _ app.Service = (*httpapi.LoginServer)(nil)

func (privateIdentityLoginServiceOptions) String() string   { return "[REDACTED]" }
func (privateIdentityLoginServiceOptions) GoString() string { return "[REDACTED]" }
func (privateIdentityLoginServiceOptions) LogValue() slog.Value {
	return slog.StringValue("[REDACTED]")
}
func (privateIdentityLoginServiceOptions) MarshalJSON() ([]byte, error) {
	return nil, errInvalidPrivateIdentityComposition
}

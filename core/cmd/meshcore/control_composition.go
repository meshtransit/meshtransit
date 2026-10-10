package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"

	"meshtransit.net/core/internal/adapter/controllistener"
	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	"meshtransit.net/core/internal/adapter/relayauthority"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidControlComposition = errors.New("invalid control composition")

// browserControlServices lets MTCP sessions register a Device through the
// browser (mtcp-v1 §6.3).
type browserControlServices struct {
	issuer     mtcpadapter.BrowserIssuer
	completion mtcpadapter.BrowserApproval
}

// composeControlListener serves MTCP v1 and, when configured, the relay
// authority's documents on the public control listener.
func composeControlListener(
	controlConfig config.ControlConfig,
	relayAuthority http.Handler,
	mtcp mtcpRoutes,
) (*controllistener.Listener, error) {
	if mtcp == nil {
		return nil, errInvalidControlComposition
	}
	telemetry, err := controllistener.NewTelemetry(controlConfig.MaxSessions)
	if err != nil {
		return nil, errors.Join(errInvalidControlComposition, err)
	}
	certificate, err := loadControlCertificate(controlConfig)
	if err != nil {
		return nil, err
	}
	listener, err := controllistener.New(controllistener.Options{
		Address:          controlConfig.Address,
		Certificate:      certificate,
		Routes:           controlRoutes{relay: relayAuthority, mtcp: mtcp},
		Telemetry:        telemetry,
		MaxConnections:   controlConfig.MaxSessions,
		HandshakeTimeout: controlConfig.HandshakeTimeout,
		IdleTimeout:      controlConfig.ReadIdleTimeout,
	})
	if err != nil {
		return nil, errors.Join(errInvalidControlComposition, err)
	}
	return listener, nil
}

// mtcpRoutes is the MTCP v1 server (mtcpadapter.Server).
type mtcpRoutes interface {
	http.Handler
	Shutdown(context.Context) error
}

// controlRoutes sends MTCP v1 paths to the MTCP server and the relay
// authority's paths to it; every other path is not found. relay may be nil.
type controlRoutes struct {
	relay http.Handler
	mtcp  mtcpRoutes
}

func (routes controlRoutes) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	switch {
	case mtcpadapter.Handles(request.URL.Path):
		routes.mtcp.ServeHTTP(response, request)
	case routes.relay != nil && strings.HasPrefix(request.URL.Path, relayauthority.PathPrefix):
		routes.relay.ServeHTTP(response, request)
	default:
		http.NotFound(response, request)
	}
}

// Shutdown closes and joins MTCP sessions, which the HTTP server stopped
// tracking when it handed their connections over.
func (routes controlRoutes) Shutdown(ctx context.Context) error {
	return routes.mtcp.Shutdown(ctx)
}

var (
	_ mtcpadapter.BrowserIssuer   = (*control.BrowserRegistrationService)(nil)
	_ mtcpadapter.BrowserApproval = (*control.BrowserCompletionService)(nil)
)

func loadControlCertificate(controlConfig config.ControlConfig) (tls.Certificate, error) {
	certificatePEM, err := controlConfig.TLSCertificateFile.Read()
	if err != nil {
		return tls.Certificate{}, errors.Join(errInvalidControlComposition, err)
	}
	defer clear(certificatePEM)
	privateKeyPEM, err := controlConfig.TLSPrivateKeyFile.Read()
	if err != nil {
		return tls.Certificate{}, errors.Join(errInvalidControlComposition, err)
	}
	defer clear(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return tls.Certificate{}, errors.Join(errInvalidControlComposition, err)
	}
	return certificate, nil
}

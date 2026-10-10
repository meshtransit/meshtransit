package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"meshtransit.net/core/internal/adapter/legacyts2021"
	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	"meshtransit.net/core/internal/adapter/relayauthority"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/enrollment/registration/intake"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidControlComposition = errors.New("invalid control composition")

type browserControlServices struct {
	issuer     legacyts2021.BrowserRegistrationService
	completion legacyts2021.BrowserCompletionService
}

func composeControlListener(
	controlConfig config.ControlConfig,
	registrationService legacyts2021.RegistrationService,
	mapSessionService legacyts2021.MapSessionService,
	mapStreamService legacyts2021.MapStreamService,
	relayAuthority http.Handler,
	mtcp mtcpRoutes,
	logger *slog.Logger,
	browser ...browserControlServices,
) (*legacyts2021.ControlListener, error) {
	if registrationService == nil || mapSessionService == nil || mapStreamService == nil ||
		logger == nil || len(browser) > 1 {
		return nil, errInvalidControlComposition
	}
	var browserServices browserControlServices
	if len(browser) == 1 {
		browserServices = browser[0]
		if browserServices.issuer == nil || browserServices.completion == nil {
			return nil, errInvalidControlComposition
		}
	}
	telemetry, err := legacyts2021.NewControlTelemetry(
		controlConfig.MaxSessions,
		controlConfig.MaxSessions,
	)
	if err != nil {
		return nil, errors.Join(errInvalidControlComposition, err)
	}
	handler, err := legacyts2021.NewCredentialRegistrationHandler(
		legacyts2021.CredentialRegistrationHandlerOptions{
			Service:    registrationService,
			Browser:    browserServices.issuer,
			Completion: browserServices.completion,
			IDs:        intake.PublicRegistrationIDGenerator{},
			Logger:     logger,
			Telemetry:  telemetry,
		},
	)
	if err != nil {
		return nil, errors.Join(errInvalidControlComposition, err)
	}
	mapHandler, err := legacyts2021.NewMapSessionHandler(
		legacyts2021.MapSessionHandlerOptions{
			Service:   mapSessionService,
			Streams:   mapStreamService,
			Logger:    logger,
			Telemetry: telemetry,
			Timeout:   controlConfig.Map.RequestTimeout,
		},
	)
	if err != nil {
		return nil, errors.Join(errInvalidControlComposition, err)
	}
	sessionRoutes, err := legacyts2021.NewAuthenticatedRoutes(handler, mapHandler)
	if err != nil {
		return nil, errors.Join(errInvalidControlComposition, err)
	}
	// Client enforcement evidence (R1-69) reaches the stream that owns it.
	if enforcement, ok := mapStreamService.(legacyts2021.EnforcementService); ok {
		enforcementHandler, handlerErr := legacyts2021.NewEnforcementHandler(enforcement, logger, telemetry)
		if handlerErr != nil {
			return nil, errors.Join(errInvalidControlComposition, handlerErr)
		}
		sessionRoutes, err = sessionRoutes.WithEnforcement(enforcementHandler)
		if err != nil {
			return nil, errors.Join(errInvalidControlComposition, err)
		}
	}

	privateKey, certificate, err := loadControlIdentity(controlConfig)
	if err != nil {
		return nil, err
	}
	sessions, err := legacyts2021.NewControlServer(legacyts2021.ControlServerOptions{
		PrivateKey:           privateKey,
		Sessions:             sessionRoutes,
		Logger:               logger,
		Telemetry:            telemetry,
		MaxSessions:          controlConfig.MaxSessions,
		MaxConcurrentStreams: controlConfig.MaxStreamsPerSession,
		HandshakeTimeout:     controlConfig.HandshakeTimeout,
		ReadIdleTimeout:      controlConfig.ReadIdleTimeout,
		PingTimeout:          controlConfig.PingTimeout,
		WriteTimeout:         controlConfig.WriteTimeout,
	})
	if err != nil {
		return nil, errors.Join(errInvalidControlComposition, err)
	}
	var routes legacyts2021.ControlSessionServer = sessions
	if relayAuthority != nil || mtcp != nil {
		routes = controlRoutes{ControlSessionServer: sessions, relay: relayAuthority, mtcp: mtcp}
	}
	listener, err := legacyts2021.NewControlListener(legacyts2021.ControlListenerOptions{
		Address:          controlConfig.Address,
		Certificate:      certificate,
		Sessions:         routes,
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

// controlRoutes serves MTCP v1 and the relay authority's public documents
// beside the TS2021 control paths on the same listener. Either may be nil.
type controlRoutes struct {
	legacyts2021.ControlSessionServer
	relay http.Handler
	mtcp  mtcpRoutes
}

func (routes controlRoutes) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	switch {
	case routes.mtcp != nil && mtcpadapter.Handles(request.URL.Path):
		routes.mtcp.ServeHTTP(response, request)
	case routes.relay != nil && strings.HasPrefix(request.URL.Path, relayauthority.PathPrefix):
		routes.relay.ServeHTTP(response, request)
	default:
		routes.ControlSessionServer.ServeHTTP(response, request)
	}
}

// Shutdown closes and joins MTCP sessions, which the HTTP server stopped
// tracking when it handed their connections over, and then TS2021 sessions.
func (routes controlRoutes) Shutdown(ctx context.Context) error {
	var mtcpErr error
	if routes.mtcp != nil {
		mtcpErr = routes.mtcp.Shutdown(ctx)
	}
	return errors.Join(mtcpErr, routes.ControlSessionServer.Shutdown(ctx))
}

var _ legacyts2021.MapSessionService = (*mapsession.Service)(nil)
var _ legacyts2021.MapStreamService = (*mapsession.StreamService)(nil)

func loadControlIdentity(
	controlConfig config.ControlConfig,
) (legacyts2021.ControlPrivateKey, tls.Certificate, error) {
	noiseMaterial, err := controlConfig.NoisePrivateKeyFile.Read()
	if err != nil {
		return legacyts2021.ControlPrivateKey{}, tls.Certificate{},
			errors.Join(errInvalidControlComposition, err)
	}
	privateKey, err := legacyts2021.ParseControlPrivateKey(noiseMaterial)
	if err != nil {
		return legacyts2021.ControlPrivateKey{}, tls.Certificate{},
			errors.Join(errInvalidControlComposition, err)
	}

	certificatePEM, err := controlConfig.TLSCertificateFile.Read()
	if err != nil {
		return legacyts2021.ControlPrivateKey{}, tls.Certificate{},
			errors.Join(errInvalidControlComposition, err)
	}
	defer clear(certificatePEM)
	privateKeyPEM, err := controlConfig.TLSPrivateKeyFile.Read()
	if err != nil {
		return legacyts2021.ControlPrivateKey{}, tls.Certificate{},
			errors.Join(errInvalidControlComposition, err)
	}
	defer clear(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return legacyts2021.ControlPrivateKey{}, tls.Certificate{},
			errors.Join(errInvalidControlComposition, err)
	}
	return privateKey, certificate, nil
}

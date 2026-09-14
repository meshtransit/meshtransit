package main

import (
	"crypto/tls"
	"errors"
	"log/slog"

	"github.com/meshtransit/meshtransit/internal/adapter/legacyts2021"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration/intake"
)

var errInvalidControlComposition = errors.New("invalid control composition")

func composeControlListener(
	controlConfig config.ControlConfig,
	registrationService legacyts2021.RegistrationService,
	logger *slog.Logger,
) (*legacyts2021.ControlListener, error) {
	if registrationService == nil || logger == nil {
		return nil, errInvalidControlComposition
	}
	handler, err := legacyts2021.NewCredentialRegistrationHandler(
		legacyts2021.CredentialRegistrationHandlerOptions{
			Service: registrationService,
			IDs:     intake.PublicRegistrationIDGenerator{},
			Logger:  logger,
		},
	)
	if err != nil {
		return nil, errors.Join(errInvalidControlComposition, err)
	}

	privateKey, certificate, err := loadControlIdentity(controlConfig)
	if err != nil {
		return nil, err
	}
	telemetry, err := legacyts2021.NewControlTelemetry(
		controlConfig.MaxSessions,
		controlConfig.MaxSessions,
	)
	if err != nil {
		return nil, errors.Join(errInvalidControlComposition, err)
	}
	sessions, err := legacyts2021.NewControlServer(legacyts2021.ControlServerOptions{
		PrivateKey:           privateKey,
		Sessions:             handler,
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
	listener, err := legacyts2021.NewControlListener(legacyts2021.ControlListenerOptions{
		Address:          controlConfig.Address,
		Certificate:      certificate,
		Sessions:         sessions,
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

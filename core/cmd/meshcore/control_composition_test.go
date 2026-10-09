package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"meshtransit.net/core/internal/adapter/legacyts2021"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/platform/config"
)

func TestComposeControlListenerLoadsTLSAndNoiseIdentity(t *testing.T) {
	t.Parallel()

	controlConfig, _ := controlConfigFixture(t)
	listener, err := composeControlListener(
		controlConfig,
		controlRegistrationServiceFixture{},
		controlMapSessionServiceFixture{},
		controlMapStreamServiceFixture{},
		nil,
		discardCompositionLogger(),
	)
	if err != nil {
		t.Fatalf("composeControlListener() error = %v", err)
	}
	if listener == nil {
		t.Fatal("composeControlListener() returned nil listener")
	}
	if listener.MetricsCollector() == nil {
		t.Fatal("composeControlListener() returned listener without telemetry")
	}
}

func TestComposeControlListenerRejectsInvalidDependencies(t *testing.T) {
	t.Parallel()

	controlConfig, _ := controlConfigFixture(t)
	tests := []struct {
		name            string
		service         controlRegistrationServiceFixture
		mapService      controlMapSessionServiceFixture
		streamService   controlMapStreamServiceFixture
		nilRegistration bool
		nilMap          bool
		nilStream       bool
		nilLog          bool
	}{
		{name: "registration service", nilRegistration: true, mapService: controlMapSessionServiceFixture{}, streamService: controlMapStreamServiceFixture{}},
		{name: "map service", service: controlRegistrationServiceFixture{}, nilMap: true, streamService: controlMapStreamServiceFixture{}},
		{name: "stream service", service: controlRegistrationServiceFixture{}, mapService: controlMapSessionServiceFixture{}, nilStream: true},
		{name: "logger", service: controlRegistrationServiceFixture{}, mapService: controlMapSessionServiceFixture{}, streamService: controlMapStreamServiceFixture{}, nilLog: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var service legacyts2021.RegistrationService = test.service
			if test.nilRegistration {
				service = nil
			}
			var mapService legacyts2021.MapSessionService = test.mapService
			if test.nilMap {
				mapService = nil
			}
			var streamService legacyts2021.MapStreamService = test.streamService
			if test.nilStream {
				streamService = nil
			}
			logger := discardCompositionLogger()
			if test.nilLog {
				logger = nil
			}
			_, err := composeControlListener(
				controlConfig,
				service,
				mapService,
				streamService,
				nil,
				logger,
			)
			if !errors.Is(err, errInvalidControlComposition) {
				t.Fatalf("composeControlListener() error = %v, want composition error", err)
			}
		})
	}
}

func TestLoadControlIdentityRejectsMaterialWithoutDisclosure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		filename string
		content  []byte
	}{
		{name: "noise key", filename: "noise.key", content: []byte("privkey:invalid")},
		{name: "certificate", filename: "certificate.pem", content: []byte("not a certificate")},
		{name: "tls key", filename: "tls.key", content: []byte("not a private key")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			controlConfig, paths := controlConfigFixture(t)
			path := paths[test.filename]
			if err := os.WriteFile(path, test.content, 0o600); err != nil {
				t.Fatalf("os.WriteFile() error = %v", err)
			}
			_, _, err := loadControlIdentity(controlConfig)
			if !errors.Is(err, errInvalidControlComposition) {
				t.Fatalf("loadControlIdentity() error = %v, want composition error", err)
			}
			if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), string(test.content)) {
				t.Fatalf("loadControlIdentity() disclosed secret material or path: %v", err)
			}
		})
	}
}

type controlRegistrationServiceFixture struct{}

func (controlRegistrationServiceFixture) Register(
	context.Context,
	control.AuthenticatedMachine,
	control.RegistrationRequest,
) (registration.Result, error) {
	return registration.Result{}, errors.New("composition fixture must not be called")
}

type controlMapSessionServiceFixture struct{}

func (controlMapSessionServiceFixture) Open(
	context.Context,
	control.AuthenticatedMachine,
	mapsession.Request,
) (mapsession.Snapshot, error) {
	return mapsession.Snapshot{}, errors.New("composition fixture must not be called")
}

type controlMapStreamServiceFixture struct{}

func (controlMapStreamServiceFixture) Serve(
	context.Context,
	control.AuthenticatedMachine,
	mapsession.Request,
	mapsession.StreamSink,
) error {
	return errors.New("composition fixture must not be called")
}

func discardCompositionLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

func controlConfigFixture(t *testing.T) (config.ControlConfig, map[string]string) {
	t.Helper()

	directory := t.TempDir()
	activePath := filepath.Join(directory, "enrollment.key")
	writeCredentialDigestTestKey(
		t,
		activePath,
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32)),
	)

	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := tlsServer.TLS.Certificates[0]
	tlsServer.Close()
	certificatePath := filepath.Join(directory, "certificate.pem")
	certificatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate.Certificate[0],
	})
	if err := os.WriteFile(certificatePath, certificatePEM, 0o600); err != nil {
		t.Fatalf("write TLS certificate: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey() error = %v", err)
	}
	privateKeyPath := filepath.Join(directory, "tls.key")
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER})
	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0o600); err != nil {
		t.Fatalf("write TLS private key: %v", err)
	}
	clear(privateKeyDER)
	clear(privateKeyPEM)

	noiseSeed := make([]byte, 32)
	if _, err := rand.Read(noiseSeed); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	noiseMaterial := []byte("privkey:" + hex.EncodeToString(noiseSeed))
	clear(noiseSeed)
	noisePath := filepath.Join(directory, "noise.key")
	if err := os.WriteFile(noisePath, noiseMaterial, 0o600); err != nil {
		t.Fatalf("write Noise private key: %v", err)
	}
	clear(noiseMaterial)

	values := credentialDigestTestValues(activePath)
	values["MESHTRANSIT_CONTROL_TLS_CERTIFICATE_FILE"] = certificatePath
	values["MESHTRANSIT_CONTROL_TLS_PRIVATE_KEY_FILE"] = privateKeyPath
	values["MESHTRANSIT_CONTROL_NOISE_PRIVATE_KEY_FILE"] = noisePath
	processConfig, err := config.Load(func(setting string) (string, bool) {
		value, ok := values[setting]
		return value, ok
	})
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if processConfig.Control == nil {
		t.Fatal("config.Load() returned nil control config")
	}
	return *processConfig.Control, map[string]string{
		"certificate.pem": certificatePath,
		"tls.key":         privateKeyPath,
		"noise.key":       noisePath,
	}
}

type routeRecorder struct{ hits int }

func (r *routeRecorder) ServeHTTP(http.ResponseWriter, *http.Request) { r.hits++ }
func (*routeRecorder) Shutdown(context.Context) error                 { return nil }

func TestRelayAuthorityRoutesSplitByPrefix(t *testing.T) {
	t.Parallel()

	control, relay := &routeRecorder{}, &routeRecorder{}
	routes := relayAuthorityRoutes{ControlSessionServer: control, relay: relay}
	for _, path := range []string{"/relay/v1/state", "/relay/v1/map", "/key", "/ts2021", "/relay/v2/state"} {
		routes.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
	}
	if relay.hits != 2 || control.hits != 3 {
		t.Fatalf("relay hits %d, control hits %d", relay.hits, control.hits)
	}
}

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

	"meshtransit.net/core/internal/adapter/controllistener"
	"meshtransit.net/core/internal/platform/config"
)

func TestComposeControlListenerLoadsTLS(t *testing.T) {
	t.Parallel()

	controlConfig, _ := controlConfigFixture(t)
	listener, err := composeControlListener(controlConfig, nil, &routeRecorder{})
	if err != nil {
		t.Fatalf("composeControlListener() error = %v", err)
	}
	if listener == nil || listener.MetricsCollector() == nil {
		t.Fatal("composeControlListener() returned no listener or no telemetry")
	}
	if _, err := composeControlListener(controlConfig, nil, nil); !errors.Is(err, errInvalidControlComposition) {
		t.Fatalf("without MTCP: error = %v, want composition error", err)
	}
}

func TestLoadControlCertificateRejectsMaterialWithoutDisclosure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		filename string
		content  []byte
	}{
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
			_, err := loadControlCertificate(controlConfig)
			if !errors.Is(err, errInvalidControlComposition) {
				t.Fatalf("loadControlCertificate() error = %v, want composition error", err)
			}
			if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), string(test.content)) {
				t.Fatalf("loadControlCertificate() disclosed secret material or path: %v", err)
			}
		})
	}
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

func TestControlRoutesSplitByPath(t *testing.T) {
	t.Parallel()

	relay, mtcp := &routeRecorder{}, &routeRecorder{}
	routes := controlRoutes{relay: relay, mtcp: mtcp}
	notFound := 0
	for _, path := range []string{"/relay/v1/state", "/relay/v1/map", "/key", "/control", "/machine/map",
		"/relay/v2/state", "/mtcp/v1", "/mtcp/v1/ws", "/mtcp/v1/key", "/mtcp/v2"} {
		response := httptest.NewRecorder()
		routes.ServeHTTP(response, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
		if response.Code == http.StatusNotFound {
			notFound++
		}
	}
	if relay.hits != 2 || mtcp.hits != 3 || notFound != 5 {
		t.Fatalf("relay hits %d, mtcp hits %d, not found %d", relay.hits, mtcp.hits, notFound)
	}
	// Without a relay authority its paths are not found either.
	response := httptest.NewRecorder()
	controlRoutes{mtcp: mtcp}.ServeHTTP(response,
		httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/relay/v1/state", nil))
	if response.Code != http.StatusNotFound || relay.hits != 2 {
		t.Fatal("a relay path was served without a relay authority")
	}
}

type shutdownRecorder struct {
	routeRecorder
	calls int
	err   error
}

func (r *shutdownRecorder) Shutdown(context.Context) error {
	r.calls++
	return r.err
}

func TestControlRoutesShutdownJoinsMTCP(t *testing.T) {
	t.Parallel()

	failure := errors.New("mtcp drain timed out")
	mtcp := &shutdownRecorder{err: failure}
	if err := (controlRoutes{mtcp: mtcp}).Shutdown(t.Context()); !errors.Is(err, failure) || mtcp.calls != 1 {
		t.Fatalf("Shutdown() = %v after %d calls", err, mtcp.calls)
	}
}

// Every session cap config accepts must compose a control listener.
func TestControlListenerAcceptsTheLargestConfiguredSessionCap(t *testing.T) {
	t.Parallel()
	if _, err := controllistener.NewTelemetry(16384); err != nil {
		t.Fatalf("NewTelemetry(16384) error = %v; config accepts MESHTRANSIT_CONTROL_MAX_SESSIONS up to 16384", err)
	}
}

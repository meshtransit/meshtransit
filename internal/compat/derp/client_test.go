package derp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshd/internal/relay"
)

func TestDialRejectsNonUpgradeResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	dialer := &Dialer{
		dialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var networkDialer net.Dialer

			return networkDialer.DialContext(ctx, network, server.Listener.Addr().String())
		},
		rootCAs: roots,
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	_, err := dialer.Dial(ctx, relay.Key{1}, relay.Region{
		ID: 1,
		Nodes: []relay.Node{{
			Name:     "relay",
			HostName: server.Certificate().DNSNames[0],
			Port:     443,
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "status 204") {
		t.Fatalf("Dial() error = %v", err)
	}
}

func TestTLSConfigVerifiesAlternateCertificateName(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	certificate := server.Certificate()
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	dialer := &Dialer{rootCAs: roots}
	config, err := dialer.tlsConfig(relay.Node{
		HostName: "front.invalid",
		CertName: certificate.DNSNames[0],
	})
	if err != nil {
		t.Fatalf("tlsConfig() error = %v", err)
	}
	if config.VerifyConnection == nil {
		t.Fatal("tlsConfig() did not install alternate-name verification")
	}
	if err := config.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
	}); err != nil {
		t.Fatalf("VerifyConnection() error = %v", err)
	}
}

func TestTLSConfigVerifiesPinnedCertificate(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(server.Close)
	certificate := server.Certificate()
	digest := sha256.Sum256(certificate.Raw)
	dialer := &Dialer{}
	config, err := dialer.tlsConfig(relay.Node{
		HostName: certificate.DNSNames[0],
		CertName: certificatePinLabel + hex.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatalf("tlsConfig() error = %v", err)
	}
	if err := config.VerifyConnection(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
	}); err != nil {
		t.Fatalf("VerifyConnection() error = %v", err)
	}
	wrongDigest := digest
	wrongDigest[0] ^= 0xff
	verifier := pinnedCertificateVerifier(certificate.DNSNames[0], wrongDigest)
	if err := verifier(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
	}); err == nil {
		t.Fatal("pinned verifier accepted wrong certificate")
	}
}

func TestTLSConfigRejectsMalformedPin(t *testing.T) {
	t.Parallel()

	dialer := &Dialer{}
	_, err := dialer.tlsConfig(relay.Node{
		HostName: "relay.example.com",
		CertName: certificatePinLabel + "01",
	})
	if err == nil {
		t.Fatal("tlsConfig() error = nil")
	}
}

func TestHeaderContainsToken(t *testing.T) {
	t.Parallel()

	if !headerContainsToken("keep-alive, Upgrade", "upgrade") {
		t.Fatal("headerContainsToken() = false")
	}
	if headerContainsToken("keep-alive", "upgrade") {
		t.Fatal("headerContainsToken() = true")
	}
}

func TestDialHonorsCancellation(t *testing.T) {
	t.Parallel()

	dialer := &Dialer{
		dialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()

			return nil, ctx.Err()
		},
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := dialer.Dial(ctx, relay.Key{1}, relay.Region{
		ID: 1,
		Nodes: []relay.Node{{
			Name:     "relay",
			HostName: "relay.example.com",
			Port:     443,
		}},
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Dial() error = %v, want context.Canceled", err)
	}
}

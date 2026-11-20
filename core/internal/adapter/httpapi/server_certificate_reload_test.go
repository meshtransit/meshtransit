package httpapi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"testing"
)

// handshakeWithoutSNI completes a TLS handshake against config the way
// ingress-nginx does by default (no SNI) and returns the served leaf.
func handshakeWithoutSNI(t *testing.T, config *tls.Config) []byte {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close(); _ = clientConn.Close() }()
	served := make(chan error, 1)
	go func() { served <- tls.Server(serverConn, config).HandshakeContext(t.Context()) }()
	// No ServerName: no SNI. The client reads the served certificate
	// instead of verifying it.
	client := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // see above
	if err := client.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("handshake without SNI: %v", err)
	}
	if err := <-served; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	peer := client.ConnectionState().PeerCertificates
	if len(peer) == 0 {
		t.Fatal("no certificate served")
	}
	return peer[0].Raw
}

func reloadingConfig(t *testing.T, config *tls.Config) {
	t.Helper()
	if len(config.Certificates) != 0 || config.GetCertificate == nil {
		t.Fatal("a reloading server must serve through GetCertificate alone")
	}
}

func TestManagementServerReloadServesClientsWithoutSNI(t *testing.T) {
	t.Parallel()
	certificate := managementTLSCertificate(t)
	server, err := NewManagementServer(ManagementServerOptions{
		Address: "127.0.0.1:8444", Certificate: certificate, Handler: http.NotFoundHandler(), MaxConnections: 2,
		Reload: func() (tls.Certificate, error) { return certificate, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	reloadingConfig(t, server.tlsConfig)
	if !bytes.Equal(handshakeWithoutSNI(t, server.tlsConfig), certificate.Certificate[0]) {
		t.Fatal("served another certificate")
	}
}

func pemReader(certificatePEM, privateKeyPEM []byte) PEMReader {
	return func() ([]byte, []byte, error) {
		return bytes.Clone(certificatePEM), bytes.Clone(privateKeyPEM), nil
	}
}

// The login server starts (its start checks the current certificate's
// validity) and serves without SNI when it reloads.
func TestLoginServerReloadServesClientsWithoutSNI(t *testing.T) {
	t.Parallel()
	options, _, _ := loginServerTestOptions(t)
	options.ReloadPEM = pemReader(options.CertificatePEM, options.PrivateKeyPEM)
	server, _ := startLoginTestServer(t, options)
	reloadingConfig(t, server.tlsConfig)
	leaf := tlsLeaf(t, options.CertificatePEM)
	if !bytes.Equal(handshakeWithoutSNI(t, server.tlsConfig), leaf) {
		t.Fatal("served another certificate")
	}
}

func TestIdentityServerReloadServesClientsWithoutSNI(t *testing.T) {
	t.Parallel()
	options := identityServerTestOptions(t, http.NotFoundHandler())
	options.ReloadPEM = pemReader(options.CertificatePEM, options.PrivateKeyPEM)
	server, err := NewIdentityServer(options)
	if err != nil {
		t.Fatal(err)
	}
	reloadingConfig(t, server.tlsConfig)
	leaf := tlsLeaf(t, options.CertificatePEM)
	if !bytes.Equal(handshakeWithoutSNI(t, server.tlsConfig), leaf) {
		t.Fatal("served another certificate")
	}
}

// A reload applies the construction's checks: a certificate for another
// host is refused, and a read error is passed on.
func TestServerCertificateLoaderChecksLikeConstruction(t *testing.T) {
	t.Parallel()
	good, goodKey, _ := loginServerTestCertificate(t, func(template *x509.Certificate) {
		template.DNSNames = []string{"id.example.test"}
	})
	other, otherKey, _ := loginServerTestCertificate(t, func(template *x509.Certificate) {
		template.DNSNames = []string{"elsewhere.example.test"}
	})
	if _, err := serverCertificateLoader("id.example.test", pemReader(good, goodKey))(); err != nil {
		t.Fatalf("matching host: %v", err)
	}
	if _, err := serverCertificateLoader("id.example.test", pemReader(other, otherKey))(); !errors.Is(err, ErrInvalidLoginServer) {
		t.Fatalf("other host: %v", err)
	}
	failed := errors.New("half-written Secret")
	if _, err := serverCertificateLoader("id.example.test", func() ([]byte, []byte, error) {
		return nil, nil, failed
	})(); !errors.Is(err, failed) {
		t.Fatalf("read error: %v", err)
	}
}

// tlsLeaf returns the DER of the first certificate in a PEM bundle.
func tlsLeaf(t *testing.T, certificatePEM []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(certificatePEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	return block.Bytes
}

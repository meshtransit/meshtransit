package controllistener

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// With Reload the listener serves through GetCertificate with Certificates
// empty, so a client that sends no SNI (ingress-nginx by default) still gets
// the certificate.
func TestListenerReloadServesClientsWithoutSNI(t *testing.T) {
	t.Parallel()
	certificate := testTLSCertificate(t)
	listener, err := New(Options{
		Address: "127.0.0.1:8443", Certificate: certificate, Routes: &fakeRoutes{},
		Telemetry: telemetryFixture(t), MaxConnections: 2, HandshakeTimeout: time.Second, IdleTimeout: time.Minute,
		Reload: func() (tls.Certificate, error) { return certificate, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(listener.tlsConfig.Certificates) != 0 || listener.tlsConfig.GetCertificate == nil {
		t.Fatal("a reloading listener must serve through GetCertificate alone")
	}
	serverConn, clientConn := net.Pipe()
	defer func() { _ = serverConn.Close(); _ = clientConn.Close() }()
	served := make(chan error, 1)
	go func() { served <- tls.Server(serverConn, listener.tlsConfig).HandshakeContext(t.Context()) }()
	// No ServerName: the client sends no SNI. It reads the served
	// certificate instead of verifying it.
	client := tls.Client(clientConn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // see above
	if err := client.HandshakeContext(t.Context()); err != nil {
		t.Fatalf("handshake without SNI: %v", err)
	}
	if err := <-served; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if peer := client.ConnectionState().PeerCertificates; len(peer) == 0 ||
		!bytes.Equal(peer[0].Raw, certificate.Certificate[0]) {
		t.Fatal("served another certificate")
	}
}

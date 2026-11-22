package postgres

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// These tests run the real pgx connect against local listeners, so a change
// in how pgx wraps its errors shows up as a wrong classification.

func listen(t *testing.T, serve func(net.Conn)) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go serve(connection)
		}
	}()
	return listener.Addr().String()
}

func connectError(t *testing.T, address, sslmode string, timeout time.Duration) error {
	t.Helper()
	config, err := pgx.ParseConfig(fmt.Sprintf("postgres://u:p@%s/db?sslmode=%s", address, sslmode))
	if err != nil {
		t.Fatal(err)
	}
	config.ConnectTimeout = timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := pgx.ConnectConfig(ctx, config)
	if err == nil {
		_ = connection.Close(ctx)
		t.Fatal("connected")
	}
	return err
}

// readStartup reads one length-prefixed startup-phase message.
func readStartup(connection net.Conn) ([]byte, error) {
	var length [4]byte
	if _, err := io.ReadFull(connection, length[:]); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint32(length[:])-4)
	_, err := io.ReadFull(connection, body)
	return body, err
}

func TestConnectErrorsFromRealConnects(t *testing.T) {
	refused := func() string {
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		address := listener.Addr().String()
		_ = listener.Close()
		return address
	}()
	hangs := listen(t, func(connection net.Conn) {
		time.Sleep(2 * time.Second)
		_ = connection.Close()
	})
	closes := listen(t, func(connection net.Conn) {
		_, _ = readStartup(connection)
		_ = connection.Close()
	})
	wrongPassword := listen(t, func(connection net.Conn) {
		defer func() { _ = connection.Close() }()
		if _, err := readStartup(connection); err != nil {
			return
		}
		fields := "SFATAL\x00VFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00"
		message := append([]byte{'E'}, binary.BigEndian.AppendUint32(nil, uint32(4+len(fields)))...) //nolint:gosec // a short constant message
		_, _ = connection.Write(append(message, fields...))
	})
	certificate := selfSigned(t)
	untrusted := listen(t, func(connection net.Conn) {
		defer func() { _ = connection.Close() }()
		if _, err := readStartup(connection); err != nil { // SSLRequest
			return
		}
		if _, err := connection.Write([]byte{'S'}); err != nil {
			return
		}
		server := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		_ = server.HandshakeContext(context.Background())
	})
	cases := []struct {
		name, address, sslmode string
		timeout                time.Duration
		transient              bool
	}{
		{"refused", refused, "disable", 2 * time.Second, true},
		// Only this case meets the connect timeout; the others answer well
		// within theirs even on a loaded machine.
		{"connect timeout", hangs, "disable", 200 * time.Millisecond, true},
		{"closed by the server", closes, "disable", 2 * time.Second, true},
		{"wrong password", wrongPassword, "disable", 2 * time.Second, false},
		{"untrusted certificate", untrusted, "verify-full", 2 * time.Second, false},
	}
	for _, test := range cases {
		err := connectError(t, test.address, test.sslmode, test.timeout)
		if got := transientConnectError(err); got != test.transient {
			t.Errorf("%s: transient = %v, want %v (%v)", test.name, got, test.transient, err)
		}
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:   time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

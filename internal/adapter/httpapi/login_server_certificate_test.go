package httpapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"
)

func TestLoginServerCertificateRejectsForeignIdentityAndUsage(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*x509.Certificate)
	}{
		{name: "foreign host", change: func(c *x509.Certificate) { c.DNSNames = []string{"foreign.example.test"} }},
		{name: "wildcard", change: func(c *x509.Certificate) { c.DNSNames = []string{"*.example.test"} }},
		{name: "shared identity", change: func(c *x509.Certificate) { c.DNSNames = append(c.DNSNames, "id.example.test") }},
		{name: "ip identity", change: func(c *x509.Certificate) { c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")} }},
		{name: "email identity", change: func(c *x509.Certificate) { c.EmailAddresses = []string{"synthetic@example.test"} }},
		{name: "uri identity", change: func(c *x509.Certificate) { c.URIs = []*url.URL{{Scheme: "https", Host: "console.example.test"}} }},
		{name: "ca certificate", change: func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }},
		{name: "client usage", change: func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth} }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options, fixture, callback := loginServerTestOptions(t)
			options.CertificatePEM, options.PrivateKeyPEM, _ = loginServerTestCertificate(t, test.change)
			if server, err := NewLoginServer(options); server != nil || !errors.Is(err, ErrInvalidLoginServer) {
				t.Fatal("foreign certificate scope released a server")
			}
			if len(fixture.calls) != 0 || callback.calls != 0 {
				t.Fatal("certificate validation performed request effects")
			}
		})
	}
	options, _, _ := loginServerTestOptions(t)
	options.CertificatePEM = bytes.Repeat(options.CertificatePEM, 9)
	if server, err := NewLoginServer(options); server != nil || !errors.Is(err, ErrInvalidLoginServer) {
		t.Fatal("unbounded certificate chain accepted")
	}
}

func TestLoginServerCertificateStrengthProfile(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		leaf     x509.Certificate
		expected bool
	}{
		{name: "ecdsa p256", leaf: x509.Certificate{SignatureAlgorithm: x509.ECDSAWithSHA256, PublicKey: &ecdsa.PublicKey{Curve: elliptic.P256()}}, expected: true},
		{name: "ecdsa p384", leaf: x509.Certificate{SignatureAlgorithm: x509.ECDSAWithSHA384, PublicKey: &ecdsa.PublicKey{Curve: elliptic.P384()}}, expected: true},
		{name: "ecdsa p521", leaf: x509.Certificate{SignatureAlgorithm: x509.ECDSAWithSHA512, PublicKey: &ecdsa.PublicKey{Curve: elliptic.P521()}}, expected: true},
		{name: "ed25519", leaf: x509.Certificate{SignatureAlgorithm: x509.PureEd25519, PublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize)}, expected: true},
		{name: "short ed25519", leaf: x509.Certificate{SignatureAlgorithm: x509.PureEd25519, PublicKey: ed25519.PublicKey{1}}},
		{name: "weak signature", leaf: x509.Certificate{SignatureAlgorithm: x509.ECDSAWithSHA1, PublicKey: &ecdsa.PublicKey{Curve: elliptic.P256()}}},
		{name: "weak rsa", leaf: x509.Certificate{SignatureAlgorithm: x509.SHA256WithRSA, PublicKey: &rsa.PublicKey{N: big.NewInt(17), E: 65537}}},
		{name: "missing rsa modulus", leaf: x509.Certificate{SignatureAlgorithm: x509.SHA256WithRSA, PublicKey: &rsa.PublicKey{E: 65537}}},
		{name: "unknown key", leaf: x509.Certificate{SignatureAlgorithm: x509.ECDSAWithSHA256, PublicKey: "unsupported"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if strongLoginCertificate(&test.leaf) != test.expected {
				t.Fatal("certificate strength profile changed")
			}
		})
	}
}

func TestLoginServerStartRejectsExpiredAndFutureCertificates(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(*x509.Certificate)
	}{
		{name: "expired", change: func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-2 * time.Hour)
			c.NotAfter = time.Now().Add(-time.Hour)
		}},
		{name: "future", change: func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(time.Hour)
			c.NotAfter = time.Now().Add(2 * time.Hour)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options, _, _ := loginServerTestOptions(t)
			options.CertificatePEM, options.PrivateKeyPEM, _ = loginServerTestCertificate(t, test.change)
			server, err := NewLoginServer(options)
			if err != nil {
				t.Fatal("effect-free construction read system time")
			}
			if !errors.Is(server.Start(t.Context()), ErrInvalidLoginServer) || server.Done() != nil {
				t.Fatal("invalid certificate validity opened a service")
			}
		})
	}
}

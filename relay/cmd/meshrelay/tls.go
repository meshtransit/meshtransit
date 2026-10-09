package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// tlsConfig builds the TLS configuration of the stream transport. TLS is not
// part of MTRP's trust model (the Noise handshake authenticates the relay),
// but a publicly trusted certificate lets middleboxes and proxies pass the
// connection, so ACME or certificate files are preferred over self-signed.
func tlsConfig(cfg serveConfig) (*tls.Config, error) {
	modes := 0
	for _, set := range []bool{cfg.tlsCert != "", cfg.acmeHost != "", cfg.tlsSelfSigned} {
		if set {
			modes++
		}
	}
	if modes != 1 {
		return nil, errors.New("--tls needs exactly one of --tls-cert/--tls-key, --acme-host or --tls-self-signed")
	}
	switch {
	case cfg.tlsCert != "":
		if cfg.tlsKey == "" {
			return nil, errors.New("--tls-cert needs --tls-key")
		}
		r, err := newCertReloader(cfg.tlsCert, cfg.tlsKey)
		if err != nil {
			return nil, err
		}
		return &tls.Config{GetCertificate: r.get, MinVersion: tls.VersionTLS13}, nil
	case cfg.acmeHost != "":
		if cfg.acmeCache == "" {
			return nil, errors.New("--acme-host needs --acme-cache")
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(cfg.acmeHost),
			Cache:      autocert.DirCache(cfg.acmeCache),
			Email:      cfg.acmeEmail,
		}
		// TLS-ALPN-01 runs on this same port; no port 80 is needed.
		c := m.TLSConfig()
		c.MinVersion = tls.VersionTLS13
		// Clients that dial the relay by address send no SNI; serve them the
		// relay's own certificate instead of failing the handshake.
		host := cfg.acmeHost
		c.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName == "" {
				named := *hello
				named.ServerName = host
				hello = &named
			}
			return m.GetCertificate(hello)
		}
		return c, nil
	default:
		cert, err := selfSigned()
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, nil
	}
}

// selfSigned creates an ephemeral certificate for test and lab deployments.
func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "meshrelay"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"meshrelay"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// certReloader serves a certificate from files and reloads it when they
// change, checking at most once a minute, so renewals need no restart.
type certReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	modTime time.Time
	checked time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := r.load(time.Now()); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) load(now time.Time) error {
	info, err := os.Stat(r.certFile)
	if err != nil {
		return fmt.Errorf("tls certificate: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("tls certificate: %w", err)
	}
	r.cert, r.modTime, r.checked = &cert, info.ModTime(), now
	return nil
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	if now.Sub(r.checked) >= time.Minute {
		r.checked = now
		if info, err := os.Stat(r.certFile); err == nil && !info.ModTime().Equal(r.modTime) {
			// A failed reload keeps the current certificate.
			_ = r.load(now)
		}
	}
	return r.cert, nil
}

package httpapi

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"slices"
	"time"
)

// Why a listener refuses its certificate, joined with the listener's own
// error: a closed reason an operator can act on, never the certificate.
var (
	// ErrServerCertificateUnreadable: the certificate or key does not
	// parse, they do not pair, a file is over 64 KiB, or the listener has
	// no host to check the certificate against.
	ErrServerCertificateUnreadable = errors.New("http api: the certificate or its key cannot be read as a pair")
	// ErrServerCertificateName: the certificate does not name the
	// listener's host alone (a wildcard or another name is refused).
	ErrServerCertificateName = errors.New("http api: the certificate must name the listener's host alone")
	// ErrServerCertificateUsage: a CA certificate, or one without the
	// server-auth extended key usage.
	ErrServerCertificateUsage = errors.New("http api: the certificate must be a server-auth leaf")
	// ErrServerCertificateStrength: a weak key or signature algorithm.
	ErrServerCertificateStrength = errors.New("http api: the certificate's key or signature is too weak")
)

func loginServerCertificate(options LoginServerOptions) (tls.Certificate, error) {
	hostname, err := loginServerHostname(options)
	if err != nil {
		return tls.Certificate{}, err
	}
	certificate, err := serverCertificate(options.CertificatePEM, options.PrivateKeyPEM, hostname)
	if err != nil {
		return tls.Certificate{}, errors.Join(ErrInvalidLoginServer, err)
	}
	return certificate, nil
}

// loginServerHostname is the callback host the certificate must name.
func loginServerHostname(options LoginServerOptions) (string, error) {
	callback, err := url.Parse(options.Dispatcher.browser.reader.route.RedirectURI())
	if err != nil || callback.Hostname() == "" {
		return "", ErrInvalidLoginServer
	}
	return callback.Hostname(), nil
}

func serverCertificate(certificatePEM, privateKeyPEM []byte, hostname string) (tls.Certificate, error) {
	validSize := len(certificatePEM) > 0 && len(certificatePEM) <= 64*1024 &&
		len(privateKeyPEM) > 0 && len(privateKeyPEM) <= 64*1024
	if !validSize || hostname == "" {
		return tls.Certificate{}, ErrServerCertificateUnreadable
	}
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil || len(certificate.Certificate) == 0 || len(certificate.Certificate) > 8 {
		return tls.Certificate{}, ErrServerCertificateUnreadable
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, ErrServerCertificateUnreadable
	}
	soleDNS := len(leaf.DNSNames) == 1 && len(leaf.IPAddresses) == 0 && leaf.DNSNames[0] == hostname
	soleIP := len(leaf.IPAddresses) == 1 && len(leaf.DNSNames) == 0 && leaf.IPAddresses[0].String() == hostname
	foreignSAN := len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0
	if (!soleDNS && !soleIP) || foreignSAN || leaf.VerifyHostname(hostname) != nil {
		return tls.Certificate{}, ErrServerCertificateName
	}
	if leaf.IsCA || !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		return tls.Certificate{}, ErrServerCertificateUsage
	}
	if !strongLoginCertificate(leaf) {
		return tls.Certificate{}, ErrServerCertificateStrength
	}
	// Parse every chain member now; Start performs only actual-clock validity.
	for _, encoded := range certificate.Certificate[1:] {
		if _, err := x509.ParseCertificate(encoded); err != nil {
			return tls.Certificate{}, ErrServerCertificateUnreadable
		}
	}
	certificate.Leaf = leaf
	return certificate, nil
}

func strongLoginCertificate(leaf *x509.Certificate) bool {
	switch leaf.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512, x509.PureEd25519:
	default:
		return false
	}
	switch key := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		return key.N != nil && key.N.BitLen() >= 2048 && key.N.BitLen() <= 8192 && key.E >= 65537
	case *ecdsa.PublicKey:
		return key.Curve == elliptic.P256() || key.Curve == elliptic.P384() || key.Curve == elliptic.P521()
	case ed25519.PublicKey:
		return len(key) == ed25519.PublicKeySize
	default:
		return false
	}
}

func validLoginCertificateTime(certificate tls.Certificate, now time.Time) bool {
	for _, encoded := range certificate.Certificate {
		parsed, err := x509.ParseCertificate(encoded)
		if err != nil || now.Before(parsed.NotBefore) || !now.Before(parsed.NotAfter) {
			return false
		}
	}
	return true
}

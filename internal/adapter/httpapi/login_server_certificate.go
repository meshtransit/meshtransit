package httpapi

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"slices"
	"time"
)

func loginServerCertificate(options LoginServerOptions) (tls.Certificate, error) {
	validSize := len(options.CertificatePEM) > 0 && len(options.CertificatePEM) <= 64*1024 &&
		len(options.PrivateKeyPEM) > 0 && len(options.PrivateKeyPEM) <= 64*1024
	if !validSize {
		return tls.Certificate{}, ErrInvalidLoginServer
	}
	certificate, err := tls.X509KeyPair(options.CertificatePEM, options.PrivateKeyPEM)
	if err != nil || len(certificate.Certificate) > 8 {
		return tls.Certificate{}, ErrInvalidLoginServer
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, ErrInvalidLoginServer
	}
	callback, err := url.Parse(options.Dispatcher.browser.reader.route.RedirectURI())
	if err != nil || callback.Hostname() == "" {
		return tls.Certificate{}, ErrInvalidLoginServer
	}
	soleDNS := len(leaf.DNSNames) == 1 && len(leaf.IPAddresses) == 0 && leaf.DNSNames[0] == callback.Hostname()
	soleIP := len(leaf.IPAddresses) == 1 && len(leaf.DNSNames) == 0 && leaf.IPAddresses[0].String() == callback.Hostname()
	foreignSAN := len(leaf.EmailAddresses) != 0 || len(leaf.URIs) != 0
	validUsage := !leaf.IsCA && slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	if (!soleDNS && !soleIP) || foreignSAN || !validUsage || leaf.VerifyHostname(callback.Hostname()) != nil {
		return tls.Certificate{}, ErrInvalidLoginServer
	}
	if !strongLoginCertificate(leaf) {
		return tls.Certificate{}, ErrInvalidLoginServer
	}
	// Parse every chain member now; Start performs only actual-clock validity.
	for _, encoded := range certificate.Certificate[1:] {
		if _, err := x509.ParseCertificate(encoded); err != nil {
			return tls.Certificate{}, ErrInvalidLoginServer
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

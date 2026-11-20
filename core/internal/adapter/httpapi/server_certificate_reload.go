package httpapi

import (
	"crypto/tls"
	"log/slog"

	"meshtransit.net/core/internal/platform/certreload"
)

// PEMReader reads a listener's certificate and private key files again. The
// caller clears both buffers.
type PEMReader func() (certificatePEM, privateKeyPEM []byte, err error)

// serverCertificateSource serves initial until the files read again pass the
// same checks serverCertificate applies at construction (hostname, key
// strength, chain), so a renewed certificate needs no restart.
func serverCertificateSource(name, hostname string, initial tls.Certificate, read PEMReader,
	logger *slog.Logger,
) (*certreload.Source, error) {
	return certreload.New(certreload.Options{
		Name: name, Initial: initial, Logger: logger, Load: serverCertificateLoader(hostname, read),
	})
}

// serverCertificateLoader reads the files and applies serverCertificate.
func serverCertificateLoader(hostname string, read PEMReader) func() (tls.Certificate, error) {
	return func() (tls.Certificate, error) {
		certificatePEM, privateKeyPEM, err := read()
		defer clear(certificatePEM)
		defer clear(privateKeyPEM)
		if err != nil {
			return tls.Certificate{}, err
		}
		return serverCertificate(certificatePEM, privateKeyPEM, hostname)
	}
}

// listenerCertificate is the certificate a handshake gets now.
func listenerCertificate(config *tls.Config, source *certreload.Source) tls.Certificate {
	if source != nil {
		return source.Current()
	}
	return config.Certificates[0]
}

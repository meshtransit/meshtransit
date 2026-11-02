package postgres

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/shared/flowlog"
)

// The receiver gets a push destination only as Core stored it to seal:
// canonical, the CA matching its hash, nothing for S3 and R2.
func TestReceiverPush(t *testing.T) {
	t.Parallel()
	ca := "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	validCA := testCertificatePEM(t)
	for name, test := range map[string]struct {
		provider string
		config   *destinationConfig
		valid    bool
	}{
		"S3 with none":   {flowlog.ProviderS3, &destinationConfig{}, true},
		"S3 with a site": {flowlog.ProviderS3, &destinationConfig{Site: "datadoghq.eu"}, false},
		"no config":      {flowlog.ProviderDatadog, nil, false},
		"datadog":        {flowlog.ProviderDatadog, &destinationConfig{Site: "datadoghq.eu"}, true},
		"a URL not canonical": {flowlog.ProviderElasticsearch, &destinationConfig{
			URL: "https://ES.example.com", Flavor: flowlog.FlavorElasticsearch}, false},
		"a CA hash without its PEM": {flowlog.ProviderElasticsearch, &destinationConfig{
			URL: "https://es.example.com:443", Flavor: flowlog.FlavorElasticsearch, CASHA256: strings.Repeat("a", 64)}, false},
		"elasticsearch with its CA": {flowlog.ProviderElasticsearch, &destinationConfig{
			URL: "https://es.example.com:443", Flavor: flowlog.FlavorElasticsearch, CAPEM: validCA,
			CASHA256: flowlog.CAHash([]byte(validCA))}, true},
		"a CA not its hash": {flowlog.ProviderElasticsearch, &destinationConfig{
			URL: "https://es.example.com:443", Flavor: flowlog.FlavorElasticsearch, CAPEM: ca,
			CASHA256: strings.Repeat("a", 64)}, false},
	} {
		destination := connectionlog.ReceiverDestination{Provider: test.provider}
		if err := receiverPush(&destination, test.config); (err == nil) != test.valid {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// testCertificatePEM is a self-signed certificate in PEM.
func testCertificatePEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, NotBefore: time.Unix(1_800_000_000, 0), NotAfter: time.Unix(1_900_000_000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

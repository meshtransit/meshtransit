package kubetrust

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

const testName = "kinda-k1.kube.000000000101.000000000201.mesh.internal"

// rootDER makes a root as Core does, then lets change alter it.
func rootDER(t *testing.T, change func(template *x509.Certificate)) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{testName},
		ExcludedIPRanges: []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		},
	}
	if change != nil {
		change(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestCheckRoot(t *testing.T) {
	t.Parallel()
	if root, err := CheckRoot(rootDER(t, nil), testName); err != nil || root == nil {
		t.Fatalf("CheckRoot() = %v", err)
	}
	for name, test := range map[string]struct {
		der  []byte
		name string
		want error
	}{
		"garbage":    {der: []byte("not a certificate"), name: testName, want: ErrMalformed},
		"other name": {der: rootDER(t, nil), name: "other.kube.example", want: ErrOtherName},
		"path length 0": {der: rootDER(t, func(template *x509.Certificate) {
			template.MaxPathLen, template.MaxPathLenZero = 0, true
		}), name: testName, want: ErrNotARoot},
		"no IP exclusion": {der: rootDER(t, func(template *x509.Certificate) {
			template.ExcludedIPRanges = nil
		}), name: testName, want: ErrNotARoot},
		"not critical": {der: rootDER(t, func(template *x509.Certificate) {
			template.PermittedDNSDomainsCritical = false
		}), name: testName, want: ErrNotARoot},
		"two names": {der: rootDER(t, func(template *x509.Certificate) {
			template.PermittedDNSDomains = append(template.PermittedDNSDomains, "other.example")
		}), name: testName, want: ErrNotARoot},
		"not a CA": {der: rootDER(t, func(template *x509.Certificate) {
			template.IsCA, template.MaxPathLen = false, -1
			template.KeyUsage = x509.KeyUsageDigitalSignature
		}), name: testName, want: ErrNotARoot},
		"an excluded domain": {der: rootDER(t, func(template *x509.Certificate) {
			template.ExcludedDNSDomains = []string{"bad.example"}
		}), name: testName, want: ErrNotARoot},
		"path length 2": {der: rootDER(t, func(template *x509.Certificate) {
			template.MaxPathLen = 2
		}), name: testName, want: ErrNotARoot},
		"another key usage": {der: rootDER(t, func(template *x509.Certificate) {
			template.KeyUsage |= x509.KeyUsageDigitalSignature
		}), name: testName, want: ErrNotARoot},
		"an extended key usage": {der: rootDER(t, func(template *x509.Certificate) {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}), name: testName, want: ErrNotARoot},
		"signed by another key": {der: signedByAnother(t), name: testName, want: ErrNotARoot},
	} {
		if _, err := CheckRoot(test.der, test.name); !errors.Is(err, test.want) {
			t.Errorf("%s: CheckRoot() = %v, want %v", name, err, test.want)
		}
	}
}

func TestValidName(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		testName: true, "a": true, "": false, "A.example": false, "-a.example": false, "a..b": false, "a.": false,
	} {
		if ValidName(name) != want {
			t.Errorf("ValidName(%q) != %v", name, want)
		}
	}
}

// signedByAnother is a root's certificate signed by a key other than its
// own: not self-signed.
func signedByAnother(t *testing.T) []byte {
	t.Helper()
	signer, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subject, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(8), Subject: pkix.Name{CommonName: "root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 1,
		KeyUsage:                    x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{testName},
		ExcludedIPRanges: []*net.IPNet{
			{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)},
			{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &subject.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

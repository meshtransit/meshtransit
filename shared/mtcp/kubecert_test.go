package mtcp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"
)

// A renewal proof binds the request to the session, the certificate renewed
// and the CSR, and only
// the current certificate's key makes one (mtcp-v1 §6.9, K1a4 a3 §3).
func TestKubeCertRenewalProof(t *testing.T) {
	t.Parallel()
	current, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	handshake := [32]byte{1}
	request := [16]byte{2}
	serial := [16]byte{3}
	csr := []byte("a CSR")
	proof, err := SignKubeCertRenewal(current, handshake, request, serial, csr)
	if err != nil || len(proof) == 0 || len(proof) > KubeCertRenewalProofMaximum {
		t.Fatalf("SignKubeCertRenewal() = %d bytes, %v", len(proof), err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&current.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyKubeCertRenewal(spki, handshake, request, serial, csr, proof) {
		t.Fatal("a good proof was refused")
	}
	otherSPKI, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	for name, verify := range map[string]bool{
		"another key":     VerifyKubeCertRenewal(otherSPKI, handshake, request, serial, csr, proof),
		"another session": VerifyKubeCertRenewal(spki, [32]byte{9}, request, serial, csr, proof),
		"another request": VerifyKubeCertRenewal(spki, handshake, [16]byte{9}, serial, csr, proof),
		"another serial":  VerifyKubeCertRenewal(spki, handshake, request, [16]byte{9}, csr, proof),
		"another CSR":     VerifyKubeCertRenewal(spki, handshake, request, serial, []byte("another"), proof),
		"no key":          VerifyKubeCertRenewal(nil, handshake, request, serial, csr, proof),
		"garbage":         VerifyKubeCertRenewal(spki, handshake, request, serial, csr, []byte("garbage")),
	} {
		if verify {
			t.Errorf("%s: verified", name)
		}
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := SignKubeCertRenewal(p384, handshake, request, serial, csr); err == nil {
		t.Fatal("a P-384 key signed")
	}
	p384SPKI, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if VerifyKubeCertRenewal(p384SPKI, handshake, request, serial, csr, proof) {
		t.Fatal("a P-384 key verified")
	}
}

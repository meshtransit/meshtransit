package oidcauth

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestBrowserProofRoundTripsAndCannotDowngradeToLegacy(t *testing.T) {
	t.Parallel()
	params := pendingParamsFixture(t)
	binding := bindingFixture(t)
	digest, err := params.DigestKey.PreAuthCookie(binding, params.Secrets.PreAuthCookie())
	if err != nil {
		t.Fatal(err)
	}
	// Public construction supplies fresh entropy for each independent envelope.
	cipher, err := NewVerifierCipher(params.VerifierCipher.ID(), bytes.Repeat([]byte{0x7b}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := cipher.SealBrowser(binding, params.Secrets.Verifier(), digest)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := cipher.OpenBrowser(binding, sealed)
	if err != nil || !proof.IsValid() || proof.Verifier().Encoded() != params.Secrets.Verifier().Encoded() ||
		!params.DigestKey.VerifyPreAuthCookie(binding, params.Secrets.PreAuthCookie(), proof.CookieDigest()) {
		t.Fatal("browser proof changed binding evidence")
	}
	if _, err := cipher.Open(binding, sealed); !errors.Is(err, ErrOpenVerifier) {
		t.Fatal("browser proof downgraded to legacy")
	}
	legacy, err := cipher.Seal(binding, params.Secrets.Verifier())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cipher.OpenBrowser(binding, legacy); !errors.Is(err, ErrOpenBrowserProof) {
		t.Fatal("legacy proof admitted browser")
	}
	other := binding
	other.TransactionID = mustTransactionID(t, "01890f00-0000-7000-8000-000000000099")
	if _, err := cipher.OpenBrowser(other, sealed); !errors.Is(err, ErrOpenBrowserProof) {
		t.Fatal("substituted binding accepted")
	}
	corrupt := sealed.Bytes()
	corrupt[len(corrupt)-1] ^= 1
	tampered, err := NewCiphertext(sealed.KeyID(), corrupt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cipher.OpenBrowser(binding, tampered); !errors.Is(err, ErrOpenBrowserProof) {
		t.Fatal("tampered proof accepted")
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if !strings.Contains(fmt.Sprintf(format, proof), "[REDACTED]") {
			t.Fatal("proof format disclosed evidence")
		}
	}
	if proof.LogValue().String() != "[REDACTED]" {
		t.Fatal("proof log disclosed evidence")
	}
	if bytes.Contains(sealed.Bytes(), []byte(params.Secrets.PreAuthCookie().Encoded())) {
		t.Fatal("ciphertext contains raw cookie")
	}
}

func TestBrowserProofRejectsInvalidCipherEvidenceAndEntropy(t *testing.T) {
	t.Parallel()
	params := pendingParamsFixture(t)
	binding := bindingFixture(t)
	digest, err := params.DigestKey.PreAuthCookie(binding, params.Secrets.PreAuthCookie())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		cipher   *VerifierCipher
		binding  Binding
		verifier Verifier
		digest   CookieDigest
	}{
		{name: "nil cipher", binding: binding, verifier: params.Secrets.Verifier(), digest: digest},
		{name: "zero cipher", cipher: &VerifierCipher{}, binding: binding, verifier: params.Secrets.Verifier(), digest: digest},
		{name: "invalid binding", cipher: params.VerifierCipher, verifier: params.Secrets.Verifier(), digest: digest},
		{name: "missing verifier", cipher: params.VerifierCipher, binding: binding, digest: digest},
		{name: "missing cookie digest", cipher: params.VerifierCipher, binding: binding, verifier: params.Secrets.Verifier()},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := test.cipher.SealBrowser(test.binding, test.verifier, test.digest); !errors.Is(err, ErrSealBrowserProof) {
				t.Fatal("invalid proof prepared")
			}
			if _, err := test.cipher.OpenBrowser(test.binding, Ciphertext{}); !errors.Is(err, ErrOpenBrowserProof) {
				t.Fatal("invalid ciphertext opened")
			}
		})
	}
	params.VerifierCipher.entropy = bytes.NewReader([]byte{1})
	if _, err := params.VerifierCipher.SealBrowser(binding, params.Secrets.Verifier(), digest); !errors.Is(err, ErrSealBrowserProof) {
		t.Fatal("entropy failure ignored")
	}
}

func TestBrowserProofRejectsAuthenticatedMalformedPayload(t *testing.T) {
	t.Parallel()
	params := pendingParamsFixture(t)
	binding := bindingFixture(t)
	// Authenticate malformed content deliberately: parser must validate beyond GCM.
	verifier := params.Secrets.Verifier()
	valid := append([]byte{browserProofVersion, 1, 'k'}, verifier.value[:]...)
	valid = append(valid, bytes.Repeat([]byte{0x53}, 32)...)
	for _, test := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "unknown version", mutate: func(b []byte) []byte { b[0]++; return b }},
		{name: "empty key", mutate: func(b []byte) []byte { b[1] = 0; return b }},
		{name: "oversized key", mutate: func(b []byte) []byte { b[1] = 129; return b }},
		{name: "invalid key", mutate: func(b []byte) []byte { b[2] = ' '; return b }},
		{name: "zero verifier", mutate: func(b []byte) []byte { clear(b[3:35]); return b }},
		{name: "zero digest", mutate: func(b []byte) []byte { clear(b[35:]); return b }},
		{name: "trailing bytes", mutate: func(b []byte) []byte { return append(b, 0) }},
		{name: "truncated", mutate: func(b []byte) []byte { return b[:len(b)-1] }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plaintext := test.mutate(bytes.Clone(valid))
			nonce := make([]byte, params.VerifierCipher.aead.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				t.Fatal(err)
			}
			value := params.VerifierCipher.aead.Seal(nonce, nonce, plaintext, browserProofBindingBytes(binding))
			sealed, err := NewCiphertext(params.VerifierCipher.ID(), value)
			if err != nil {
				t.Fatal(err)
			}
			proof, err := params.VerifierCipher.OpenBrowser(binding, sealed)
			if !errors.Is(err, ErrOpenBrowserProof) || proof.IsValid() {
				t.Fatal("authenticated malformed proof accepted")
			}
		})
	}
}

func FuzzParseBrowserProof(f *testing.F) {
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{1}, 67))
	f.Fuzz(func(t *testing.T, value []byte) {
		proof, err := parseBrowserProof(value)
		if err == nil && (!proof.IsValid() || len(value) != browserProofFixedBytes+len(proof.CookieDigest().KeyID().String())) {
			t.Fatal("noncanonical proof accepted")
		}
	})
}

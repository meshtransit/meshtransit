package oidcauth

import (
	"bytes"
	"errors"
	"testing"
)

func TestVerifierCipherRoundTripsExactBinding(t *testing.T) {
	t.Parallel()

	keyID, err := NewVerifierEncryptionKeyID("oidc-aead-v1")
	if err != nil {
		t.Fatalf("NewVerifierEncryptionKeyID() error = %v", err)
	}
	verifierCipher, err := newVerifierCipher(
		keyID,
		bytes.Repeat([]byte{0x7b}, 32),
		bytes.NewReader(bytes.Repeat([]byte{0x8c}, 12)),
	)
	if err != nil {
		t.Fatalf("newVerifierCipher() error = %v", err)
	}
	binding := bindingFixture(t)
	verifier := secretFixture(t).Verifier()
	ciphertext, err := verifierCipher.Seal(binding, verifier)
	if err != nil {
		t.Fatalf("VerifierCipher.Seal() error = %v", err)
	}
	opened, err := verifierCipher.Open(binding, ciphertext)
	if err != nil {
		t.Fatalf("VerifierCipher.Open() error = %v", err)
	}
	if opened.Encoded() != verifier.Encoded() {
		t.Fatal("VerifierCipher.Open() changed verifier material")
	}
	stored := ciphertext.Bytes()
	stored[0] ^= 0xff
	if bytes.Equal(stored, ciphertext.Bytes()) {
		t.Fatal("Ciphertext.Bytes() exposed mutable internal storage")
	}

	other := binding
	other.ClientID = mustClientID(t, "01890f00-0000-7000-8000-000000000099")
	if _, err := verifierCipher.Open(other, ciphertext); !errors.Is(err, ErrOpenVerifier) {
		t.Fatalf("VerifierCipher.Open(substituted binding) error = %v, want ErrOpenVerifier", err)
	}
	other = binding
	other.ReturnRouteID = "account.settings"
	if _, err := verifierCipher.Open(other, ciphertext); !errors.Is(err, ErrOpenVerifier) {
		t.Fatalf("VerifierCipher.Open(substituted return route) error = %v, want ErrOpenVerifier", err)
	}
}

func TestVerifierCipherRejectsEntropyFailure(t *testing.T) {
	t.Parallel()

	keyID, err := NewVerifierEncryptionKeyID("oidc-aead-v1")
	if err != nil {
		t.Fatalf("NewVerifierEncryptionKeyID() error = %v", err)
	}
	verifierCipher, err := newVerifierCipher(
		keyID,
		bytes.Repeat([]byte{0x7b}, 32),
		bytes.NewReader([]byte{0x01}),
	)
	if err != nil {
		t.Fatalf("newVerifierCipher() error = %v", err)
	}
	_, err = verifierCipher.Seal(bindingFixture(t), secretFixture(t).Verifier())
	if !errors.Is(err, ErrSealVerifier) {
		t.Fatalf("VerifierCipher.Seal() error = %v, want ErrSealVerifier", err)
	}
}

func bindingFixture(t *testing.T) Binding {
	t.Helper()
	route := routeFixture(t)
	binding, err := route.Binding(
		mustTransactionID(t, "01890f00-0000-7000-8000-000000000005"),
	)
	if err != nil {
		t.Fatalf("Route.Binding() error = %v", err)
	}
	return binding
}

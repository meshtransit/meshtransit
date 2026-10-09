package oidcauth

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
)

const (
	browserProofBindingDomain      = "meshtransit/oidc-auth/browser-proof/v1\x00"
	browserProofVersion       byte = 1
	browserProofFixedBytes         = 2 + transactionSecretBytes + sha256.Size
)

var (
	// ErrSealBrowserProof reports failure to encrypt complete browser-binding evidence.
	ErrSealBrowserProof = errors.New("oidc auth: seal browser proof")
	// ErrOpenBrowserProof reports invalid, substituted, legacy, or unbound evidence.
	ErrOpenBrowserProof = errors.New("oidc auth: open browser proof")
)

// BrowserProof contains recovered PKCE and cookie digest evidence, never a raw cookie.
type BrowserProof struct {
	verifier     Verifier
	cookieDigest CookieDigest
}

// Verifier explicitly releases token-endpoint proof material after browser validation.
func (proof BrowserProof) Verifier() Verifier { return proof.verifier }

// CookieDigest returns the exact generation and evidence for cookie verification.
func (proof BrowserProof) CookieDigest() CookieDigest { return proof.cookieDigest }

// IsValid reports whether both independent evidence dimensions are present.
func (proof BrowserProof) IsValid() bool {
	return proof.verifier.IsValid() && proof.cookieDigest.IsValid()
}

// String prevents accidental proof disclosure.
func (BrowserProof) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed proof disclosure.
func (BrowserProof) GoString() string { return "oidcauth.BrowserProof([REDACTED])" }

// LogValue prevents accidental structured-log proof disclosure.
func (BrowserProof) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// SealBrowser authenticates a versioned browser payload under a distinct AEAD purpose.
// The storage algorithm/nonce envelope stays unchanged; verifier-only openers fail closed.
func (verifierCipher *VerifierCipher) SealBrowser(
	binding Binding,
	verifier Verifier,
	cookieDigest CookieDigest,
) (Ciphertext, error) {
	invalidCipher := verifierCipher == nil || !verifierCipher.ID().IsValid()
	if invalidCipher || verifierCipher.aead == nil || verifierCipher.entropy == nil ||
		!binding.IsValid() || !verifier.IsValid() || !cookieDigest.IsValid() {
		return Ciphertext{}, ErrSealBrowserProof
	}
	keyID := cookieDigest.KeyID().String()
	keyBytes := len(keyID)
	if keyBytes < 1 || keyBytes > 128 {
		return Ciphertext{}, ErrSealBrowserProof
	}
	plaintext := make([]byte, browserProofFixedBytes+keyBytes)
	defer clear(plaintext)
	plaintext[0], plaintext[1] = browserProofVersion, byte(keyBytes)
	copy(plaintext[2:], keyID)
	copy(plaintext[2+len(keyID):], verifier.value[:])
	digestBytes := cookieDigest.Bytes()
	copy(plaintext[2+len(keyID)+transactionSecretBytes:], digestBytes[:])
	nonce := make([]byte, verifierCipher.aead.NonceSize())
	defer clear(nonce)
	if _, err := io.ReadFull(verifierCipher.entropy, nonce); err != nil {
		return Ciphertext{}, fmt.Errorf("%w: %w", ErrSealBrowserProof, err)
	}
	sealed := verifierCipher.aead.Seal(nil, nonce, plaintext, browserProofBindingBytes(binding))
	defer clear(sealed)
	value := make([]byte, 0, len(nonce)+len(sealed))
	value = append(value, nonce...)
	value = append(value, sealed...)
	return Ciphertext{keyID: verifierCipher.id, value: value}, nil
}

// OpenBrowser authenticates the exact binding and rejects verifier-only or malformed payloads.
// Cookie verification must precede callback claiming, token exchange, or use of the verifier.
func (verifierCipher *VerifierCipher) OpenBrowser(binding Binding, ciphertext Ciphertext) (BrowserProof, error) {
	invalidCipher := verifierCipher == nil || !verifierCipher.ID().IsValid()
	if invalidCipher || verifierCipher.aead == nil || !binding.IsValid() ||
		!ciphertext.IsValid() || ciphertext.KeyID() != verifierCipher.ID() {
		return BrowserProof{}, ErrOpenBrowserProof
	}
	nonceSize := verifierCipher.aead.NonceSize()
	payloadBytes := len(ciphertext.value) - nonceSize - verifierCipher.aead.Overhead()
	if payloadBytes < browserProofFixedBytes+1 || payloadBytes > browserProofFixedBytes+128 {
		return BrowserProof{}, ErrOpenBrowserProof
	}
	plaintext, err := verifierCipher.aead.Open(
		nil,
		ciphertext.value[:nonceSize],
		ciphertext.value[nonceSize:],
		browserProofBindingBytes(binding),
	)
	if err != nil {
		return BrowserProof{}, ErrOpenBrowserProof
	}
	defer clear(plaintext)
	return parseBrowserProof(plaintext)
}

func parseBrowserProof(plaintext []byte) (BrowserProof, error) {
	if len(plaintext) < browserProofFixedBytes+1 || plaintext[0] != browserProofVersion {
		return BrowserProof{}, ErrOpenBrowserProof
	}
	keyBytes := int(plaintext[1])
	if keyBytes < 1 || keyBytes > 128 || len(plaintext) != browserProofFixedBytes+keyBytes {
		return BrowserProof{}, ErrOpenBrowserProof
	}
	keyID, err := NewDigestKeyID(string(plaintext[2 : 2+keyBytes]))
	if err != nil {
		return BrowserProof{}, ErrOpenBrowserProof
	}
	var verifierValue [transactionSecretBytes]byte
	copy(verifierValue[:], plaintext[2+keyBytes:2+keyBytes+transactionSecretBytes])
	var digestValue [sha256.Size]byte
	copy(digestValue[:], plaintext[2+keyBytes+transactionSecretBytes:])
	digest, err := NewCookieDigest(DigestAlgorithmHMACSHA256V1, keyID, digestValue)
	proof := BrowserProof{verifier: Verifier{value: verifierValue}, cookieDigest: digest}
	if err != nil || !proof.IsValid() {
		return BrowserProof{}, ErrOpenBrowserProof
	}
	return proof, nil
}

func browserProofBindingBytes(binding Binding) []byte {
	encoded := []byte(browserProofBindingDomain)
	return append(encoded, verifierBindingBytes(binding)...)
}

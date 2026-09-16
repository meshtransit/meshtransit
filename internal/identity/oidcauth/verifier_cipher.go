package oidcauth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const (
	// VerifierEncryptionAlgorithmAES256GCMV1 identifies the durable envelope format.
	VerifierEncryptionAlgorithmAES256GCMV1 = "aead-aes-256-gcm-v1"
	verifierEncryptionKeyBytes             = 32
	verifierBindingDomain                  = "meshtransit/oidc-auth/pkce-verifier/v1\x00"
	maximumRedirectIDBytes                 = 128
)

var (
	// ErrInvalidVerifierEncryptionKey reports malformed key identity or material.
	ErrInvalidVerifierEncryptionKey = errors.New("oidc auth: invalid verifier encryption key")
	// ErrInvalidBinding reports an incomplete or ambiguous transaction binding.
	ErrInvalidBinding = errors.New("oidc auth: invalid transaction binding")
	// ErrSealVerifier reports failure to encrypt a PKCE verifier.
	ErrSealVerifier = errors.New("oidc auth: seal pkce verifier")
	// ErrOpenVerifier reports invalid, substituted, or undecryptable verifier evidence.
	ErrOpenVerifier = errors.New("oidc auth: open pkce verifier")
)

// VerifierEncryptionKeyID identifies one versioned AEAD key.
type VerifierEncryptionKeyID struct{ value string }

// NewVerifierEncryptionKeyID validates a bounded public key identifier.
func NewVerifierEncryptionKeyID(value string) (VerifierEncryptionKeyID, error) {
	if !validKeyID(value) {
		return VerifierEncryptionKeyID{}, ErrInvalidVerifierEncryptionKey
	}
	return VerifierEncryptionKeyID{value: value}, nil
}

// String returns the non-secret key generation.
func (id VerifierEncryptionKeyID) String() string { return id.value }

// IsValid reports whether the key identifier remains canonical.
func (id VerifierEncryptionKeyID) IsValid() bool { return validKeyID(id.value) }

// Binding fixes encrypted verifier custody to one exact authority context.
type Binding struct {
	DeploymentID       deployment.ID
	WorkspaceID        workspace.ID
	ProviderID         ProviderID
	ClientID           ClientID
	TransactionID      TransactionID
	ProviderGeneration int64
	RecoveryEpoch      int64
	RedirectID         string
}

// IsValid reports whether every authority dimension is exact and bounded.
func (binding Binding) IsValid() bool {
	return binding.DeploymentID.IsValid() && binding.WorkspaceID.IsValid() &&
		binding.ProviderID.IsValid() && binding.ClientID.IsValid() &&
		binding.TransactionID.IsValid() && binding.ProviderGeneration > 0 &&
		binding.RecoveryEpoch > 0 && validRouteID(binding.RedirectID)
}

// VerifierCipher encrypts PKCE verifier material under one resident AEAD key.
type VerifierCipher struct {
	id      VerifierEncryptionKeyID
	aead    cipher.AEAD
	entropy io.Reader
}

// NewVerifierCipher constructs an AES-256-GCM verifier envelope.
func NewVerifierCipher(
	id VerifierEncryptionKeyID,
	material []byte,
) (*VerifierCipher, error) {
	return newVerifierCipher(id, material, rand.Reader)
}

func newVerifierCipher(
	id VerifierEncryptionKeyID,
	material []byte,
	entropy io.Reader,
) (*VerifierCipher, error) {
	if !id.IsValid() || len(material) != verifierEncryptionKeyBytes || entropy == nil {
		return nil, ErrInvalidVerifierEncryptionKey
	}
	var key [verifierEncryptionKeyBytes]byte
	copy(key[:], material)
	if key == ([verifierEncryptionKeyBytes]byte{}) {
		clear(key[:])
		return nil, ErrInvalidVerifierEncryptionKey
	}
	block, err := aes.NewCipher(key[:])
	clear(key[:])
	if err != nil {
		return nil, ErrInvalidVerifierEncryptionKey
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidVerifierEncryptionKey
	}
	return &VerifierCipher{id: id, aead: aead, entropy: entropy}, nil
}

// Seal encrypts one verifier and authenticates every authority dimension.
func (verifierCipher *VerifierCipher) Seal(
	binding Binding,
	verifier Verifier,
) (Ciphertext, error) {
	if verifierCipher == nil || !verifierCipher.id.IsValid() || verifierCipher.aead == nil ||
		verifierCipher.entropy == nil || !binding.IsValid() || !verifier.IsValid() {
		return Ciphertext{}, ErrSealVerifier
	}
	nonce := make([]byte, verifierCipher.aead.NonceSize())
	if _, err := io.ReadFull(verifierCipher.entropy, nonce); err != nil {
		clear(nonce)
		return Ciphertext{}, fmt.Errorf("%w: %w", ErrSealVerifier, err)
	}
	plaintext := []byte(verifier.Encoded())
	aad := verifierBindingBytes(binding)
	sealed := verifierCipher.aead.Seal(nil, nonce, plaintext, aad)
	clear(plaintext)
	value := make([]byte, 0, len(nonce)+len(sealed))
	value = append(value, nonce...)
	value = append(value, sealed...)
	clear(nonce)
	clear(sealed)
	return Ciphertext{keyID: verifierCipher.id, value: value}, nil
}

// Open authenticates the binding before returning token-endpoint proof material.
func (verifierCipher *VerifierCipher) Open(
	binding Binding,
	ciphertext Ciphertext,
) (Verifier, error) {
	if verifierCipher == nil || verifierCipher.aead == nil || !verifierCipher.id.IsValid() ||
		!binding.IsValid() || !ciphertext.IsValid() || ciphertext.keyID != verifierCipher.id {
		return Verifier{}, ErrOpenVerifier
	}
	nonceSize := verifierCipher.aead.NonceSize()
	if len(ciphertext.value) <= nonceSize+verifierCipher.aead.Overhead() {
		return Verifier{}, ErrOpenVerifier
	}
	nonce := ciphertext.value[:nonceSize]
	sealed := ciphertext.value[nonceSize:]
	plaintext, err := verifierCipher.aead.Open(
		nil,
		nonce,
		sealed,
		verifierBindingBytes(binding),
	)
	if err != nil {
		return Verifier{}, ErrOpenVerifier
	}
	defer clear(plaintext)
	verifier, err := ParseVerifier(string(plaintext))
	if err != nil {
		return Verifier{}, ErrOpenVerifier
	}
	return verifier, nil
}

// ID returns the public key generation.
func (verifierCipher *VerifierCipher) ID() VerifierEncryptionKeyID {
	if verifierCipher == nil {
		return VerifierEncryptionKeyID{}
	}
	return verifierCipher.id
}

// String prevents accidental resident-key disclosure.
func (*VerifierCipher) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed resident-key disclosure.
func (*VerifierCipher) GoString() string { return "oidcauth.VerifierCipher([REDACTED])" }

// LogValue prevents accidental structured-log key disclosure.
func (*VerifierCipher) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// Ciphertext is bounded verifier evidence safe for durable storage.
type Ciphertext struct {
	keyID VerifierEncryptionKeyID
	value []byte
}

// NewCiphertext validates verifier evidence loaded from durable storage.
func NewCiphertext(
	keyID VerifierEncryptionKeyID,
	value []byte,
) (Ciphertext, error) {
	if !keyID.IsValid() || len(value) < 29 || len(value) > 4096 {
		return Ciphertext{}, ErrOpenVerifier
	}
	return Ciphertext{keyID: keyID, value: bytes.Clone(value)}, nil
}

// Algorithm returns the fixed envelope algorithm.
func (Ciphertext) Algorithm() string { return VerifierEncryptionAlgorithmAES256GCMV1 }

// KeyID returns the public encryption key generation.
func (ciphertext Ciphertext) KeyID() VerifierEncryptionKeyID { return ciphertext.keyID }

// Bytes returns a defensive copy for persistence.
func (ciphertext Ciphertext) Bytes() []byte { return bytes.Clone(ciphertext.value) }

// IsValid reports whether ciphertext evidence is bounded and non-empty.
func (ciphertext Ciphertext) IsValid() bool {
	return ciphertext.keyID.IsValid() && len(ciphertext.value) >= 29 &&
		len(ciphertext.value) <= 4096
}

// String prevents accidental ciphertext disclosure.
func (Ciphertext) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed ciphertext disclosure.
func (Ciphertext) GoString() string { return "oidcauth.Ciphertext([REDACTED])" }

// LogValue prevents accidental structured-log ciphertext disclosure.
func (Ciphertext) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

func verifierBindingBytes(binding Binding) []byte {
	buffer := bytes.NewBuffer(make([]byte, 0, 192))
	buffer.WriteString(verifierBindingDomain)
	deploymentID := binding.DeploymentID.Bytes()
	workspaceID := binding.WorkspaceID.Bytes()
	providerID := binding.ProviderID.Bytes()
	clientID := binding.ClientID.Bytes()
	transactionID := binding.TransactionID.Bytes()
	buffer.Write(deploymentID[:])
	buffer.Write(workspaceID[:])
	buffer.Write(providerID[:])
	buffer.Write(clientID[:])
	buffer.Write(transactionID[:])
	_ = binary.Write(buffer, binary.BigEndian, binding.ProviderGeneration)
	_ = binary.Write(buffer, binary.BigEndian, binding.RecoveryEpoch)
	buffer.WriteString(binding.RedirectID)
	return buffer.Bytes()
}

func validRouteID(value string) bool {
	if len(value) == 0 || len(value) > maximumRedirectIDBytes || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '.' || character == '_' || character == ':' || character == '-' {
			continue
		}
		return false
	}
	return true
}

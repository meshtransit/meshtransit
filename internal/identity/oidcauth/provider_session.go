package oidcauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"log/slog"
)

// ProviderSessionKey owns resident upstream-session HMAC material, not bearer
// or stable-subject verification. Composition must load an independent key.
type ProviderSessionKey struct{ key DigestKey }

// NewProviderSessionKey validates and copies a dedicated 256-bit key.
func NewProviderSessionKey(id DigestKeyID, material []byte) (ProviderSessionKey, error) {
	key, err := NewDigestKey(id, material)
	if err != nil {
		return ProviderSessionKey{}, err
	}
	return ProviderSessionKey{key: key}, nil
}

// ProviderSessionDigest is optional versioned SID evidence, never raw SID.
type ProviderSessionDigest struct{ digest SubjectDigest }

// IsValid reports present, well-formed SID evidence; zero means absent.
func (digest ProviderSessionDigest) IsValid() bool { return digest.digest.IsValid() }

// Algorithm returns the fixed durable algorithm for present evidence.
func (digest ProviderSessionDigest) Algorithm() string { return digest.digest.Algorithm() }

// KeyID returns the resident SID key version.
func (digest ProviderSessionDigest) KeyID() DigestKeyID { return digest.digest.KeyID() }

// Bytes returns a defensive copy to the trusted persistence boundary.
func (digest ProviderSessionDigest) Bytes() [32]byte { return digest.digest.Bytes() }

func (key ProviderSessionKey) session(route Route, identity ExternalIdentity) (ProviderSessionDigest, error) {
	if !key.key.isValid() || !route.IsValid() || !identity.IsValid() || identity.Issuer() != route.Issuer() {
		return ProviderSessionDigest{}, ErrInvalidExchange
	}
	if identity.SessionID() == "" {
		return ProviderSessionDigest{}, nil
	}
	mac := hmac.New(sha256.New, key.key.material[:])
	_, _ = mac.Write([]byte("meshtransit/oidc-auth/provider-session/v1\x00"))
	dep, provider := route.DeploymentID().Bytes(), route.ProviderID().Bytes()
	_, _ = mac.Write(dep[:])
	_, _ = mac.Write(provider[:])
	for _, field := range []string{key.key.ID().String(), identity.Issuer(), identity.SessionID()} {
		// Each field is validated <=2048 bytes by route/identity/key constructors.
		length := len(field)
		if length <= 0 || length > 65535 {
			return ProviderSessionDigest{}, ErrInvalidExchange
		}
		_, _ = mac.Write(binary.BigEndian.AppendUint16(nil, uint16(length)))
		_, _ = mac.Write([]byte(field))
	}
	var value [32]byte
	copy(value[:], mac.Sum(nil))
	digest, err := NewSubjectDigest(key.key.ID(), value)
	return ProviderSessionDigest{digest: digest}, err
}

// String redacts resident material.
func (ProviderSessionKey) String() string { return "[REDACTED]" }

// GoString redacts detailed material.
func (ProviderSessionKey) GoString() string { return "oidcauth.ProviderSessionKey([REDACTED])" }

// LogValue redacts structured material.
func (ProviderSessionKey) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// String redacts SID verifier evidence.
func (ProviderSessionDigest) String() string { return "[REDACTED]" }

// GoString redacts detailed SID verifier evidence.
func (ProviderSessionDigest) GoString() string { return "oidcauth.ProviderSessionDigest([REDACTED])" }

// LogValue redacts structured SID verifier evidence.
func (ProviderSessionDigest) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

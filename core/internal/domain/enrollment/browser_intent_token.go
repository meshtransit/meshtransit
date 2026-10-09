package enrollment

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"log/slog"
	"strings"

	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
)

const (
	browserIntentTokenDomain  = "meshtransit/browser-registration-token/v1\x00"
	browserIntentDigestDomain = "meshtransit/browser-registration-lookup/v1\x00"
)

// ErrInvalidBrowserIntentToken reports malformed or invalid browser-token state.
var ErrInvalidBrowserIntentToken = errors.New("enrollment: invalid browser intent token state")

// BrowserIntentKeyID identifies a dedicated browser-token derivation key.
type BrowserIntentKeyID struct{ value string }

// NewBrowserIntentKeyID validates the durable version identifier.
func NewBrowserIntentKeyID(value string) (BrowserIntentKeyID, error) {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value ||
		!asciiAlphaNumeric(value[0]) {
		return BrowserIntentKeyID{}, ErrInvalidBrowserIntentToken
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !asciiAlphaNumeric(character) && character != '.' && character != '_' &&
			character != ':' && character != '-' {
			return BrowserIntentKeyID{}, ErrInvalidBrowserIntentToken
		}
	}
	return BrowserIntentKeyID{value: value}, nil
}

// String returns the non-secret key version.
func (id BrowserIntentKeyID) String() string { return id.value }

// IsValid reports whether the key version is canonical.
func (id BrowserIntentKeyID) IsValid() bool {
	validated, err := NewBrowserIntentKeyID(id.value)
	return err == nil && validated == id
}

// BrowserIntentNonce is a server-generated random seed persisted with an intent.
// It does not grant access without the dedicated HMAC key.
type BrowserIntentNonce [32]byte

// NewBrowserIntentNonce creates a fresh 256-bit intent nonce.
func NewBrowserIntentNonce() (BrowserIntentNonce, error) {
	var nonce BrowserIntentNonce
	if _, err := rand.Read(nonce[:]); err != nil {
		return BrowserIntentNonce{}, err
	}
	if nonce == (BrowserIntentNonce{}) {
		return BrowserIntentNonce{}, ErrInvalidBrowserIntentToken
	}
	return nonce, nil
}

// ParseBrowserIntentNonce validates a nonce loaded from durable storage.
func ParseBrowserIntentNonce(raw [32]byte) (BrowserIntentNonce, error) {
	nonce := BrowserIntentNonce(raw)
	if nonce == (BrowserIntentNonce{}) {
		return BrowserIntentNonce{}, ErrInvalidBrowserIntentToken
	}
	return nonce, nil
}

// Bytes returns a copy for the persistence adapter.
func (nonce BrowserIntentNonce) Bytes() [32]byte { return [32]byte(nonce) }

func (BrowserIntentNonce) String() string { return "[REDACTED]" }

// GoString redacts the nonce in diagnostic formatting.
func (BrowserIntentNonce) GoString() string { return "enrollment.BrowserIntentNonce([REDACTED])" }

// LogValue redacts the nonce in structured logging.
func (BrowserIntentNonce) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON rejects accidental serialization of the persisted nonce.
func (BrowserIntentNonce) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidBrowserIntentToken
}

// BrowserIntentToken is the one bearer returned inside the browser AuthURL.
type BrowserIntentToken struct{ value [32]byte }

// Encoded returns the canonical 43-character URL-safe token for delivery.
func (token BrowserIntentToken) Encoded() string {
	return base64.RawURLEncoding.EncodeToString(token.value[:])
}

func (BrowserIntentToken) String() string { return "[REDACTED]" }

// GoString redacts the bearer token in diagnostic formatting.
func (BrowserIntentToken) GoString() string { return "enrollment.BrowserIntentToken([REDACTED])" }

// LogValue redacts the bearer token in structured logging.
func (BrowserIntentToken) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON rejects accidental serialization of the URL bearer.
func (BrowserIntentToken) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidBrowserIntentToken
}

// BrowserIntentDigest is the non-bearer lookup verifier stored with the intent.
type BrowserIntentDigest struct{ value [32]byte }

// ParseBrowserIntentDigest validates a verifier loaded from durable storage.
func ParseBrowserIntentDigest(raw [32]byte) (BrowserIntentDigest, error) {
	digest := BrowserIntentDigest{value: raw}
	if !digest.valid() {
		return BrowserIntentDigest{}, ErrInvalidBrowserIntentToken
	}
	return digest, nil
}

// Bytes returns a copy for the persistence adapter.
func (digest BrowserIntentDigest) Bytes() [32]byte { return digest.value }

func (BrowserIntentDigest) String() string { return "[REDACTED]" }

// GoString redacts the token digest in diagnostic formatting.
func (BrowserIntentDigest) GoString() string { return "enrollment.BrowserIntentDigest([REDACTED])" }

// LogValue redacts the token digest in structured logging.
func (BrowserIntentDigest) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON rejects accidental serialization of lookup evidence.
func (BrowserIntentDigest) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidBrowserIntentToken
}

// BrowserIntentKey is independent from credential and Account Session keys.
type BrowserIntentKey struct {
	id       BrowserIntentKeyID
	material [32]byte
}

// NewBrowserIntentKey validates and copies dedicated HMAC key material.
func NewBrowserIntentKey(id BrowserIntentKeyID, material []byte) (BrowserIntentKey, error) {
	if !id.IsValid() || len(material) != 32 {
		return BrowserIntentKey{}, ErrInvalidBrowserIntentToken
	}
	key := BrowserIntentKey{id: id}
	copy(key.material[:], material)
	if key.material == ([32]byte{}) {
		return BrowserIntentKey{}, ErrInvalidBrowserIntentToken
	}
	return key, nil
}

func (BrowserIntentKey) String() string { return "[REDACTED]" }

// GoString redacts the signing key in diagnostic formatting.
func (BrowserIntentKey) GoString() string { return "enrollment.BrowserIntentKey([REDACTED])" }

// LogValue redacts the signing key in structured logging.
func (BrowserIntentKey) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON rejects accidental serialization of HMAC key material.
func (BrowserIntentKey) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidBrowserIntentToken
}

// BrowserIntentKeyring keeps exactly one active and at most one previous key.
type BrowserIntentKeyring struct {
	active   BrowserIntentKey
	previous BrowserIntentKey
	hasPrior bool
}

func (BrowserIntentKeyring) String() string { return "[REDACTED]" }

// GoString redacts the keyring in diagnostic formatting.
func (BrowserIntentKeyring) GoString() string { return "enrollment.BrowserIntentKeyring([REDACTED])" }

// LogValue redacts the keyring in structured logging.
func (BrowserIntentKeyring) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON rejects accidental serialization of the keyring.
func (BrowserIntentKeyring) MarshalJSON() ([]byte, error) {
	return nil, ErrInvalidBrowserIntentToken
}

// NewBrowserIntentKeyring creates the bounded key rotation window.
func NewBrowserIntentKeyring(active BrowserIntentKey, previous ...BrowserIntentKey) (*BrowserIntentKeyring, error) {
	if !active.valid() || len(previous) > 1 {
		return nil, ErrInvalidBrowserIntentToken
	}
	keyring := &BrowserIntentKeyring{active: active}
	if len(previous) == 0 {
		return keyring, nil
	}
	if !previous[0].valid() || previous[0].id == active.id ||
		hmac.Equal(previous[0].material[:], active.material[:]) {
		return nil, ErrInvalidBrowserIntentToken
	}
	keyring.previous = previous[0]
	keyring.hasPrior = true
	return keyring, nil
}

// Issue derives an unpredictable token and its stored verifier from a new
// durable nonce. A retry must call Reissue against the same saved intent.
func (keyring *BrowserIntentKeyring) Issue(
	deploymentID deployment.ID,
	recoveryEpoch int64,
	intentID BrowserIntentID,
	nonce BrowserIntentNonce,
) (BrowserIntentToken, BrowserIntentDigest, BrowserIntentKeyID, error) {
	if keyring == nil || !keyring.active.valid() {
		return BrowserIntentToken{}, BrowserIntentDigest{}, BrowserIntentKeyID{}, ErrInvalidBrowserIntentToken
	}
	token, digest, err := deriveBrowserIntentToken(
		keyring.active, deploymentID, recoveryEpoch, intentID, nonce,
	)
	return token, digest, keyring.active.id, err
}

// Reissue reproduces the exact active URL token after a retry or restart. An
// unknown key ID or mismatched persisted digest fails closed.
func (keyring *BrowserIntentKeyring) Reissue(
	deploymentID deployment.ID,
	recoveryEpoch int64,
	intentID BrowserIntentID,
	nonce BrowserIntentNonce,
	keyID BrowserIntentKeyID,
	stored BrowserIntentDigest,
) (BrowserIntentToken, error) {
	if keyring == nil || !stored.valid() || !keyID.IsValid() {
		return BrowserIntentToken{}, ErrInvalidBrowserIntentToken
	}
	key := keyring.active
	if key.id != keyID {
		if !keyring.hasPrior || keyring.previous.id != keyID {
			return BrowserIntentToken{}, ErrInvalidBrowserIntentToken
		}
		key = keyring.previous
	}
	token, actual, err := deriveBrowserIntentToken(key, deploymentID, recoveryEpoch, intentID, nonce)
	if err != nil || subtle.ConstantTimeCompare(actual.value[:], stored.value[:]) != 1 {
		return BrowserIntentToken{}, ErrInvalidBrowserIntentToken
	}
	return token, nil
}

// DigestPresentedBrowserIntentToken validates the canonical URL token and
// derives its database lookup verifier without retaining the bearer text.
func DigestPresentedBrowserIntentToken(encoded string) (BrowserIntentDigest, error) {
	if len(encoded) != 43 {
		return BrowserIntentDigest{}, ErrInvalidBrowserIntentToken
	}
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return BrowserIntentDigest{}, ErrInvalidBrowserIntentToken
	}
	var token BrowserIntentToken
	copy(token.value[:], decoded)
	clear(decoded)
	if token.value == ([32]byte{}) {
		return BrowserIntentDigest{}, ErrInvalidBrowserIntentToken
	}
	return digestBrowserIntentToken(token), nil
}

func deriveBrowserIntentToken(
	key BrowserIntentKey,
	deploymentID deployment.ID,
	recoveryEpoch int64,
	intentID BrowserIntentID,
	nonce BrowserIntentNonce,
) (BrowserIntentToken, BrowserIntentDigest, error) {
	if !key.valid() || !deploymentID.IsValid() || recoveryEpoch <= 0 ||
		!intentID.IsValid() || nonce == (BrowserIntentNonce{}) {
		return BrowserIntentToken{}, BrowserIntentDigest{}, ErrInvalidBrowserIntentToken
	}
	mac := hmac.New(sha256.New, key.material[:])
	_, _ = mac.Write([]byte(browserIntentTokenDomain))
	deploymentBytes := deploymentID.Bytes()
	intentBytes := intentID.Bytes()
	_, _ = mac.Write(deploymentBytes[:])
	var epoch [8]byte
	binary.BigEndian.PutUint64(epoch[:], uint64(recoveryEpoch))
	_, _ = mac.Write(epoch[:])
	_, _ = mac.Write(intentBytes[:])
	_, _ = mac.Write(nonce[:])
	var token BrowserIntentToken
	copy(token.value[:], mac.Sum(nil))
	return token, digestBrowserIntentToken(token), nil
}

func digestBrowserIntentToken(token BrowserIntentToken) BrowserIntentDigest {
	hash := sha256.New()
	_, _ = hash.Write([]byte(browserIntentDigestDomain))
	_, _ = hash.Write(token.value[:])
	var digest BrowserIntentDigest
	copy(digest.value[:], hash.Sum(nil))
	return digest
}

func (key BrowserIntentKey) valid() bool {
	return key.id.IsValid() && key.material != ([32]byte{})
}

func (digest BrowserIntentDigest) valid() bool { return digest.value != ([32]byte{}) }

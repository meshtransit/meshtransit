package installsecrets

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"

	"meshtransit.net/shared/key"
)

// ErrValue reports a value that does not have its item's form. It never
// carries the value.
var ErrValue = errors.New("install secrets: value has the wrong form")

const (
	randomBytes        = 32
	minimumPassword    = 32
	maximumPassword    = 256
	minimumClientValue = 32
	maximumValue       = 4096
)

var controlKey = regexp.MustCompile(`^privkey:[0-9a-f]{64}$`)

// Generate returns a new value of kind, read from random.
func Generate(kind Kind, random io.Reader) ([]byte, error) {
	buffer := make([]byte, randomBytes)
	defer clear(buffer)
	if _, err := io.ReadFull(random, buffer); err != nil {
		return nil, fmt.Errorf("install secrets: entropy: %w", err)
	}
	switch kind {
	case KindLoginPassword, KindRedisPassword:
		return []byte(hex.EncodeToString(buffer[:24])), nil
	case KindKey, KindWrapKey:
		return []byte(base64.RawURLEncoding.EncodeToString(buffer)), nil
	case KindClientSecret:
		return []byte(hex.EncodeToString(buffer)), nil
	case KindControlKey:
		return []byte("privkey:" + hex.EncodeToString(buffer)), nil
	case KindBrowserKey:
		return []byte(base64.StdEncoding.EncodeToString(buffer)), nil
	default:
		return nil, fmt.Errorf("%w: kind %d", ErrPlan, kind)
	}
}

// Normalize returns value without a trailing CRLF and then LF (as Core's
// secret files are read) and checks it has the form Core's reader of kind
// takes, so an installer's hand-made value passes exactly when Core would
// accept it.
func Normalize(kind Kind, value []byte) ([]byte, error) {
	if len(value) == 0 || len(value) > maximumValue {
		return nil, ErrValue
	}
	trimmed := bytes.TrimSuffix(bytes.TrimSuffix(value, []byte("\r\n")), []byte("\n"))
	if !validForm(kind, trimmed) {
		return nil, ErrValue
	}
	return trimmed, nil
}

func validForm(kind Kind, value []byte) bool {
	switch kind {
	case KindLoginPassword:
		return printablePassword(value, "'\\")
	case KindRedisPassword:
		return printablePassword(value, "")
	case KindKey:
		decoded, err := decodeKey(value)
		defer clear(decoded)
		return err == nil && !allZero(decoded)
	case KindWrapKey:
		decoded, err := decodeLenientKey(value)
		defer clear(decoded)
		return err == nil && !allZero(decoded)
	case KindClientSecret:
		return len(value) >= minimumClientValue && visibleASCII(value)
	case KindControlKey:
		return controlKey.Match(value) && !allZero(bytes.TrimLeft(value[len("privkey:"):], "0"))
	case KindBrowserKey:
		if bytes.ContainsAny(value, "\r\n") {
			return false
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(string(value))
		defer clear(decoded)
		return err == nil && len(decoded) == randomBytes && !allZero(decoded)
	default:
		return false
	}
}

// allZero reports an empty or all-zero key, which every key reader refuses.
func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func visibleASCII(value []byte) bool {
	for _, character := range value {
		if character <= ' ' || character > '~' {
			return false
		}
	}
	return true
}

// printablePassword is 32–256 printable ASCII characters, none a space or
// one of refused.
func printablePassword(value []byte, refused string) bool {
	if len(value) < minimumPassword || len(value) > maximumPassword {
		return false
	}
	for _, character := range value {
		if character <= ' ' || character > '~' || bytes.IndexByte([]byte(refused), character) >= 0 {
			return false
		}
	}
	return true
}

// decodeKey reads 32 bytes in canonical base64url without padding: the
// value must be exactly the encoding of what it decodes to (Go's decoder
// skips line endings; Core's readers do not).
func decodeKey(value []byte) ([]byte, error) {
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(value)))
	n, err := base64.RawURLEncoding.Strict().Decode(decoded, value)
	if err != nil || n != randomBytes || base64.RawURLEncoding.EncodeToString(decoded[:n]) != string(value) {
		clear(decoded)
		return nil, ErrValue
	}
	return decoded[:n], nil
}

// decodeLenientKey reads 32 bytes in base64, URL-safe or standard, with or
// without padding, not requiring canonical trailing bits: what the wrap-key
// reader accepts.
func decodeLenientKey(value []byte) ([]byte, error) {
	canonical := bytes.TrimRight(value, "=")
	canonical = bytes.ReplaceAll(bytes.ReplaceAll(canonical, []byte("+"), []byte("-")), []byte("/"), []byte("_"))
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(canonical)))
	n, err := base64.RawURLEncoding.Decode(decoded, canonical)
	if err != nil || n != randomBytes || bytes.ContainsAny(canonical, "\r\n") {
		clear(decoded)
		return nil, ErrValue
	}
	return decoded[:n], nil
}

// PublicHalf derives the public half of a normalized value of item, in the
// form its reader takes: relay signing in "mtsign:" form (the relay's
// trusted keys), connection-log signing as base64url Ed25519 (the api's
// token keys), the installation key in standard base64 (entitlementissue).
func PublicHalf(item Item, value []byte) (string, error) {
	if item.Public == PublicNone || item.Kind != KindKey {
		return "", fmt.Errorf("%w: %s has no public half", ErrPlan, item.ID)
	}
	seed, err := decodeKey(value)
	if err != nil {
		return "", err
	}
	defer clear(seed)
	switch item.Public {
	case PublicRelaySigning:
		signing, err := key.SigningPrivateFromSeed(seed)
		if err != nil {
			return "", ErrValue
		}
		return signing.Public().String(), nil
	case PublicFlowLogSigning:
		return base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)), nil
	case PublicInstallation:
		return base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)), nil
	default:
		return "", fmt.Errorf("%w: public %q", ErrPlan, item.Public)
	}
}

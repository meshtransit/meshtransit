package controlplane

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

const (
	privateKeyPrefix = "privkey:"
	controlKeyPrefix = "mkey:"
	keySize          = 32
)

// ParsePrivateKey decodes a canonical "privkey:<hex>" key. Callers clear
// the returned array when done.
func ParsePrivateKey(text []byte) ([keySize]byte, error) {
	return parseKey(text, privateKeyPrefix)
}

// ParseControlPublicKey decodes a canonical "mkey:<hex>" control key.
func ParseControlPublicKey(text []byte) ([keySize]byte, error) {
	return parseKey(text, controlKeyPrefix)
}

func parseKey(text []byte, prefix string) ([keySize]byte, error) {
	encoded, found := bytes.CutPrefix(text, []byte(prefix))
	var out [keySize]byte
	if !found || len(encoded) != 2*keySize {
		return out, ErrInvalidMaterial
	}
	if _, err := hex.Decode(out[:], encoded); err != nil || out == ([keySize]byte{}) ||
		!bytes.Equal(encoded, []byte(hex.EncodeToString(out[:]))) {
		clear(out[:])
		return [keySize]byte{}, ErrInvalidMaterial
	}
	return out, nil
}

// EncodePrivateKey returns the "privkey:<hex>" form.
func EncodePrivateKey(raw [keySize]byte) []byte {
	return []byte(privateKeyPrefix + hex.EncodeToString(raw[:]))
}

// EncodeControlPublicKey returns the "mkey:<hex>" form.
func EncodeControlPublicKey(raw [keySize]byte) []byte {
	return []byte(controlKeyPrefix + hex.EncodeToString(raw[:]))
}

// GenerateNodePrivateKey returns a fresh clamped X25519 key in its text form.
func GenerateNodePrivateKey() ([]byte, error) {
	var raw [keySize]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	defer clear(raw[:])
	raw[0] &= 248
	raw[31] = (raw[31] & 127) | 64
	return EncodePrivateKey(raw), nil
}

// NodePrivateRaw decodes the node key of material. Callers clear the
// returned array after transferring it to the packet engine.
func NodePrivateRaw(material KeyMaterial) ([keySize]byte, error) {
	return ParsePrivateKey(material.NodePrivateKey)
}

// ControlKeyFingerprint is the operator-facing pin of a control key:
// "sha256:" and the SHA-256 of its "mkey:<hex>" form.
func ControlKeyFingerprint(public [keySize]byte) string {
	digest := sha256.Sum256(EncodeControlPublicKey(public))
	return "sha256:" + hex.EncodeToString(digest[:])
}

// VerifyFingerprint compares an expected pin with an actual one in constant
// time and returns the canonical form.
func VerifyFingerprint(expected, actual string) (string, error) {
	canonicalExpected, err := CanonicalFingerprint(expected)
	if err != nil {
		return "", err
	}
	canonicalActual, err := CanonicalFingerprint(actual)
	if err != nil {
		return "", ErrFingerprintMismatch
	}
	if subtle.ConstantTimeCompare([]byte(canonicalExpected), []byte(canonicalActual)) != 1 {
		return "", ErrFingerprintMismatch
	}
	return canonicalExpected, nil
}

// CanonicalFingerprint validates a "sha256:<64 hex>" pin and lowercases it.
func CanonicalFingerprint(value string) (string, error) {
	value = strings.TrimSpace(value)
	if len(value) != len("sha256:")+64 || !strings.EqualFold(value[:len("sha256:")], "sha256:") {
		return "", ErrInvalidFingerprint
	}
	digest, err := hex.DecodeString(value[len("sha256:"):])
	if err != nil || len(digest) != 32 {
		return "", ErrInvalidFingerprint
	}
	return "sha256:" + hex.EncodeToString(digest), nil
}

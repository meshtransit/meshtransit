package mtrp

import (
	"encoding/binary"
	"errors"
	"slices"

	"meshtransit.net/shared/key"
)

// DocumentKind identifies a Core-signed document (mtrp-v1 §8, §9).
type DocumentKind uint8

// Document kinds. Each kind has its own signing domain, so a signature over
// one kind can never be replayed as another.
const (
	DocumentRelayMap   DocumentKind = 1
	DocumentRelayState DocumentKind = 2
)

// Document limits.
const (
	documentHeaderSize = 4 + 1 + 1 + key.KeyIDSize + 4
	signatureSize      = 64
	// MaxDocumentPayload bounds a signed document's payload.
	MaxDocumentPayload = 8 << 20
)

var documentMagic = [4]byte{'M', 'T', 'S', 'D'}

var (
	// ErrDocumentMalformed reports a signed document that violates the format.
	ErrDocumentMalformed = errors.New("mtrp: malformed signed document")
	// ErrDocumentSignature reports a document with an unknown key or a bad
	// signature.
	ErrDocumentSignature = errors.New("mtrp: signed document not authentic")
)

func (k DocumentKind) domain() (string, bool) {
	switch k {
	case DocumentRelayMap:
		return "meshtransit/relay-map/v1", true
	case DocumentRelayState:
		return "meshtransit/relay-state/v1", true
	default:
		return "", false
	}
}

// SignDocument wraps payload in a signed document:
//
//	magic "MTSD" || version u8 = 1 || kind u8 || key_id bytes[8] ||
//	payload_len u32 || payload || signature bytes[64]
//
// The Ed25519 signature covers domain || 0x00 || every preceding byte.
func SignDocument(kind DocumentKind, payload []byte, signer key.SigningPrivate) ([]byte, error) {
	domain, ok := kind.domain()
	if !ok || signer.IsZero() || len(payload) == 0 || len(payload) > MaxDocumentPayload {
		return nil, ErrDocumentMalformed
	}
	id := signer.Public().ID()
	out := make([]byte, 0, documentHeaderSize+len(payload)+signatureSize)
	out = append(out, documentMagic[:]...)
	out = append(out, 1, byte(kind))
	out = append(out, id[:]...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(payload))) //nolint:gosec // bounded by MaxDocumentPayload
	out = append(out, payload...)
	return append(out, signer.Sign(documentSigningInput(domain, out))...), nil
}

// OpenDocument verifies a signed document of the expected kind and returns
// its payload (aliasing b) and the signing key ID. Nothing is parsed before
// the signature verifies.
func OpenDocument(b []byte, kind DocumentKind, keys KeySet) ([]byte, key.KeyID, error) {
	var id key.KeyID
	domain, ok := kind.domain()
	if !ok || keys == nil || len(b) < documentHeaderSize+1+signatureSize {
		return nil, id, ErrDocumentMalformed
	}
	if [4]byte(b[:4]) != documentMagic || b[4] != 1 || DocumentKind(b[5]) != kind {
		return nil, id, ErrDocumentMalformed
	}
	copy(id[:], b[6:6+key.KeyIDSize])
	n := int(binary.BigEndian.Uint32(b[6+key.KeyIDSize : documentHeaderSize]))
	if n == 0 || n > MaxDocumentPayload || len(b) != documentHeaderSize+n+signatureSize {
		return nil, id, ErrDocumentMalformed
	}
	public, ok := keys.SigningKey(id)
	if !ok || public.ID() != id {
		return nil, id, ErrDocumentSignature
	}
	body := b[:documentHeaderSize+n]
	if !public.Verify(documentSigningInput(domain, body), b[documentHeaderSize+n:]) {
		return nil, id, ErrDocumentSignature
	}
	return b[documentHeaderSize : documentHeaderSize+n], id, nil
}

func documentSigningInput(domain string, body []byte) []byte {
	return slices.Concat([]byte(domain), []byte{0}, body)
}

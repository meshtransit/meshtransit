package disco

import (
	"bytes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"meshtransit.net/shared/key"
)

const (
	magicSize    = 6
	nonceSize    = chacha20poly1305.NonceSizeX
	headerSize   = magicSize + key.Size + nonceSize
	minPacketLen = headerSize + chacha20poly1305.Overhead + 2

	kdfSalt = "meshtransit/disco/v2\x00"
)

// Magic starts every disco v2 envelope.
var Magic = [magicSize]byte{0x4D, 0x54, 0x44, 0x32, 0xC0, 0xDE}

var (
	// ErrNotDisco reports a packet that is not a disco v2 envelope.
	ErrNotDisco = errors.New("disco: not a disco v2 packet")
	// ErrWrongSender reports an envelope from a disco key other than the peer's.
	ErrWrongSender = errors.New("disco: unexpected sender")
	// ErrAuth reports an envelope that failed authentication.
	ErrAuth = errors.New("disco: authentication failed")
)

// LooksLikeDisco reports whether a packet carries the disco v2 magic and a
// plausible length. It is a cheap demultiplexing test, not authentication.
func LooksLikeDisco(packet []byte) bool {
	return len(packet) >= minPacketLen && len(packet) <= MaxPacketSize && bytes.Equal(packet[:magicSize], Magic[:])
}

// Sender returns the sender disco key of a packet so the caller can find the
// peer. The packet is not authenticated yet.
func Sender(packet []byte) (key.DiscoPublic, error) {
	var sender key.DiscoPublic
	if !LooksLikeDisco(packet) {
		return sender, ErrNotDisco
	}
	copy(sender[:], packet[magicSize:magicSize+key.Size])
	return sender, nil
}

// PeerKey holds the message key shared with one peer. It is safe for
// concurrent use: cipher.AEAD values from chacha20poly1305 are stateless.
type PeerKey struct {
	self key.DiscoPublic
	peer key.DiscoPublic
	aead cipher.AEAD
}

// NewPeerKey derives the key for (self, peer) as specified in disco-v2 §1.
func NewPeerKey(self key.DiscoPrivate, peer key.DiscoPublic) (*PeerKey, error) {
	if self.IsZero() || peer.IsZero() {
		return nil, key.ErrInvalid
	}
	shared, err := self.Shared(peer)
	if err != nil {
		return nil, err
	}
	k, err := deriveKey(shared, self.Public(), peer)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(k[:])
	if err != nil {
		return nil, fmt.Errorf("disco: aead: %w", err)
	}
	return &PeerKey{self: self.Public(), peer: peer, aead: aead}, nil
}

func deriveKey(shared [key.Size]byte, a, b key.DiscoPublic) ([chacha20poly1305.KeySize]byte, error) {
	lo, hi := a, b
	if bytes.Compare(lo[:], hi[:]) > 0 {
		lo, hi = hi, lo
	}
	info := make([]byte, 0, 2*key.Size)
	info = append(append(info, lo[:]...), hi[:]...)
	var out [chacha20poly1305.KeySize]byte
	derived, err := hkdf.Key(sha256.New, shared[:], []byte(kdfSalt), string(info), len(out))
	if err != nil {
		return out, fmt.Errorf("disco: hkdf: %w", err)
	}
	copy(out[:], derived)
	return out, nil
}

// Peer returns the peer disco key this PeerKey talks to.
func (k *PeerKey) Peer() key.DiscoPublic { return k.peer }

// Seal encrypts m into a new envelope appended to dst. random must be a
// CSPRNG (crypto/rand.Reader); it supplies the 24-byte nonce.
func (k *PeerKey) Seal(dst []byte, m Message, random io.Reader) ([]byte, error) {
	if k == nil || random == nil {
		return nil, key.ErrInvalid
	}
	plaintext, err := appendPlaintext(make([]byte, 0, 96), m)
	if err != nil {
		return nil, err
	}
	start := len(dst)
	dst = append(dst, Magic[:]...)
	dst = append(dst, k.self[:]...)
	nonceAt := len(dst)
	dst = append(dst, make([]byte, nonceSize)...)
	if _, err := io.ReadFull(random, dst[nonceAt:]); err != nil {
		return nil, fmt.Errorf("disco: nonce: %w", err)
	}
	aad := dst[start:nonceAt]
	nonce := dst[nonceAt : nonceAt+nonceSize]
	return k.aead.Seal(dst, nonce, plaintext, aad), nil
}

// Open authenticates and decodes an envelope from this peer. Any failure
// leaves no state behind and must not trigger a reply.
func (k *PeerKey) Open(packet []byte) (Message, error) {
	if k == nil {
		return nil, key.ErrInvalid
	}
	sender, err := Sender(packet)
	if err != nil {
		return nil, err
	}
	if !key.Equal(sender, k.peer) {
		return nil, ErrWrongSender
	}
	aad := packet[:magicSize+key.Size]
	nonce := packet[magicSize+key.Size : headerSize]
	plaintext, err := k.aead.Open(nil, nonce, packet[headerSize:], aad)
	if err != nil {
		return nil, ErrAuth
	}
	return ParsePlaintext(plaintext)
}

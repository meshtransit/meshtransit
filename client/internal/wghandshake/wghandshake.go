// Package wghandshake reads which peer sent a WireGuard handshake
// initiation. meshd installs only active peers in wireguard-go, which drops
// an initiation from a peer it does not have; the bind checks each
// initiation first and installs the sender when the map allows it, so the
// handshake succeeds on the first try. It runs the responder's first Noise
// IK steps exactly as wireguard-go does (MAC1, ephemeral, encrypted static)
// with wireguard-go's own primitives; the timestamp and replay checks stay
// in wireguard-go.
package wghandshake

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
)

// Layout of a handshake initiation (WireGuard whitepaper §5.4.2).
const (
	initiationSize   = device.MessageInitiationSize
	ephemeralOffset  = 8
	staticOffset     = ephemeralOffset + curve25519.PointSize
	staticSealedSize = curve25519.PointSize + chacha20poly1305.Overhead
)

// Responder holds what checking initiations to one static key needs.
type Responder struct {
	private [32]byte
	// keyedHash is HASH(InitialHash || our public key).
	keyedHash [blake2s.Size]byte
	mac1      device.CookieChecker
}

// NewResponder prepares checks for initiations sent to the public key of
// private.
func NewResponder(private [32]byte) (*Responder, error) {
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		return nil, errors.New("wghandshake: invalid private key")
	}
	responder := &Responder{private: private}
	responder.keyedHash = mixHash(device.InitialHash, public)
	var noisePublic device.NoisePublicKey
	copy(noisePublic[:], public)
	responder.mac1.Init(noisePublic)
	return responder, nil
}

// Initiator returns the static public key of the peer that sent packet, a
// handshake initiation addressed to this responder. It reports false for any
// other packet, a wrong MAC1 or an undecryptable static key.
func (r *Responder) Initiator(packet []byte) ([32]byte, bool) {
	if r == nil || len(packet) != initiationSize ||
		binary.LittleEndian.Uint32(packet) != device.MessageInitiationType ||
		!r.mac1.CheckMAC1(packet) {
		return [32]byte{}, false
	}
	ephemeral := packet[ephemeralOffset:staticOffset]
	sealed := packet[staticOffset : staticOffset+staticSealedSize]

	hash := mixHash(r.keyedHash, ephemeral)
	var chainKey [blake2s.Size]byte
	device.KDF1(&chainKey, device.InitialChainKey[:], ephemeral)
	shared, err := curve25519.X25519(r.private[:], ephemeral)
	if err != nil {
		return [32]byte{}, false // low-order point
	}
	var key [chacha20poly1305.KeySize]byte
	device.KDF2(&chainKey, &key, chainKey[:], shared)
	defer func() {
		clear(shared)
		clear(key[:])
		clear(chainKey[:])
	}()
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return [32]byte{}, false
	}
	var initiator [32]byte
	if _, err := aead.Open(initiator[:0], device.ZeroNonce[:], sealed, hash[:]); err != nil {
		return [32]byte{}, false
	}
	if subtle.ConstantTimeCompare(initiator[:], make([]byte, 32)) == 1 {
		return [32]byte{}, false
	}
	return initiator, true
}

func mixHash(h [blake2s.Size]byte, data []byte) [blake2s.Size]byte {
	hash, _ := blake2s.New256(nil)
	hash.Write(h[:])
	hash.Write(data)
	var sum [blake2s.Size]byte
	hash.Sum(sum[:0])
	return sum
}

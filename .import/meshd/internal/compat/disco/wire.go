// Package disco implements the bounded encrypted path-probe wire adapter used
// for interoperability. Product path selection remains in pathdiscovery.
package disco

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/nacl/box"
)

const (
	magic             = "TS💬"
	nonceSize         = 24
	maxPacketSize     = 2048
	wrapperHeaderSize = len(magic) + keySize + nonceSize
	maxPlaintextSize  = maxPacketSize - wrapperHeaderSize - box.Overhead
	minPacketSize     = wrapperHeaderSize + box.Overhead + messageHeaderSize
)

var (
	// ErrNotPacket means the datagram does not belong to this wire protocol.
	ErrNotPacket = errors.New("disco: packet does not match wire protocol")
	// ErrAuthentication means ciphertext authentication failed.
	ErrAuthentication = errors.New("disco: packet authentication failed")
	// ErrUnexpectedPeer means the authenticated channel does not match the
	// sender key carried by the packet.
	ErrUnexpectedPeer = errors.New("disco: unexpected peer")
)

// LooksLikePacket reports whether a datagram belongs to this protocol's demux.
// It intentionally accepts a truncated encrypted body so malformed protocol
// traffic cannot fall through to the WireGuard parser.
func LooksLikePacket(packet []byte) bool {
	return len(packet) >= len(magic)+keySize &&
		bytes.Equal(packet[:len(magic)], []byte(magic))
}

// Source returns the untrusted sender key carried by the cleartext wrapper.
// Callers must use a control-authorized Peer and successfully Open the packet
// before trusting that identity.
func Source(packet []byte) (PublicKey, error) {
	if !LooksLikePacket(packet) {
		return PublicKey{}, ErrNotPacket
	}
	var raw [keySize]byte
	copy(raw[:], packet[len(magic):len(magic)+keySize])
	key, err := PublicKeyFromRaw(raw)
	if err != nil {
		return PublicKey{}, ErrMalformed
	}

	return key, nil
}

// Seal encrypts and authenticates one bounded message for this peer.
func (p *Peer) Seal(message Message) ([]byte, error) {
	if p == nil {
		return nil, ErrClosed
	}
	p.mu.RLock()
	isClosed := p.isClosed
	p.mu.RUnlock()
	if isClosed {
		return nil, ErrClosed
	}
	plaintext, err := marshalMessage(message)
	if err != nil {
		return nil, err
	}
	if len(plaintext) > maxPlaintextSize {
		return nil, ErrMalformed
	}

	p.mu.RLock()
	if p.isClosed || p.random == nil {
		p.mu.RUnlock()

		return nil, ErrClosed
	}
	random := p.random
	p.mu.RUnlock()
	var nonce [nonceSize]byte
	if _, err := io.ReadFull(random, nonce[:]); err != nil {
		return nil, fmt.Errorf("disco: generating nonce: %w", err)
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.isClosed {
		return nil, ErrClosed
	}
	packet := make([]byte, 0, wrapperHeaderSize+box.Overhead+len(plaintext))
	packet = append(packet, magic...)
	packet = append(packet, p.local.raw[:]...)
	packet = append(packet, nonce[:]...)
	packet = box.SealAfterPrecomputation(packet, plaintext, &nonce, &p.shared)

	return packet, nil
}

// Open authenticates, decrypts, and parses one packet from this peer.
func (p *Peer) Open(packet []byte) (Message, error) {
	if p == nil {
		return nil, ErrClosed
	}
	if len(packet) < minPacketSize || len(packet) > maxPacketSize {
		if !LooksLikePacket(packet) {
			return nil, ErrNotPacket
		}

		return nil, ErrMalformed
	}
	sender, err := Source(packet)
	if err != nil {
		return nil, err
	}

	p.mu.RLock()
	if p.isClosed {
		p.mu.RUnlock()

		return nil, ErrClosed
	}
	if sender != p.remote {
		p.mu.RUnlock()

		return nil, ErrUnexpectedPeer
	}
	var nonce [nonceSize]byte
	copy(nonce[:], packet[len(magic)+keySize:wrapperHeaderSize])
	plaintext, authenticated := box.OpenAfterPrecomputation(
		nil,
		packet[wrapperHeaderSize:],
		&nonce,
		&p.shared,
	)
	p.mu.RUnlock()
	if !authenticated {
		return nil, ErrAuthentication
	}
	defer clear(plaintext)

	return parseMessage(plaintext)
}

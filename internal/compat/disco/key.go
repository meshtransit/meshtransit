package disco

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	keySize         = 32
	publicKeyPrefix = "discokey:"
	nodeKeyPrefix   = "nodekey:"
)

var (
	// ErrInvalidKey means a discovery or node key is malformed or unsafe.
	ErrInvalidKey = errors.New("disco: invalid key")
	// ErrClosed means secret material has already been destroyed.
	ErrClosed = errors.New("disco: key material is closed")
)

// PublicKey is a validated peer-discovery public key.
type PublicKey struct {
	raw [keySize]byte
}

// ParsePublicKey parses the canonical typed key received through the control
// compatibility adapter.
func ParsePublicKey(text string) (PublicKey, error) {
	raw, err := parseTypedKey(text, publicKeyPrefix)
	if err != nil {
		return PublicKey{}, err
	}

	return PublicKey{raw: raw}, nil
}

// PublicKeyFromRaw validates a public key read from a peer packet.
func PublicKeyFromRaw(raw [keySize]byte) (PublicKey, error) {
	if isZero(raw[:]) {
		return PublicKey{}, ErrInvalidKey
	}

	return PublicKey{raw: raw}, nil
}

// IsZero reports whether the public key is unset.
func (k PublicKey) IsZero() bool { return isZero(k.raw[:]) }

// Raw returns the fixed-size public representation used by compatibility
// adapters. It contains no private material.
func (k PublicKey) Raw() [keySize]byte { return k.raw }

// String returns the canonical control-protocol representation.
func (k PublicKey) String() string {
	if k.IsZero() {
		return ""
	}

	return publicKeyPrefix + hex.EncodeToString(k.raw[:])
}

// NodeKey is the sender's validated WireGuard public identity.
type NodeKey struct {
	raw [keySize]byte
}

// ParseNodeKey parses a canonical typed node public key.
func ParseNodeKey(text string) (NodeKey, error) {
	raw, err := parseTypedKey(text, nodeKeyPrefix)
	if err != nil {
		return NodeKey{}, err
	}

	return NodeKey{raw: raw}, nil
}

// NodeKeyFromRaw validates a node public key read from a peer packet.
func NodeKeyFromRaw(raw [keySize]byte) (NodeKey, error) {
	if isZero(raw[:]) {
		return NodeKey{}, ErrInvalidKey
	}

	return NodeKey{raw: raw}, nil
}

// IsZero reports whether the node public key is unset.
func (k NodeKey) IsZero() bool { return isZero(k.raw[:]) }

// Raw returns the fixed-size public representation.
func (k NodeKey) Raw() [keySize]byte { return k.raw }

// String returns the canonical control-protocol representation.
func (k NodeKey) String() string {
	if k.IsZero() {
		return ""
	}

	return nodeKeyPrefix + hex.EncodeToString(k.raw[:])
}

// Identity owns one ephemeral discovery private key. It is safe for concurrent
// peer construction and closure.
type Identity struct {
	mu       sync.RWMutex
	private  [keySize]byte
	public   PublicKey
	isClosed bool
}

// NewIdentity creates an ephemeral discovery identity using crypto/rand.
func NewIdentity() (*Identity, error) {
	return newIdentity(rand.Reader)
}

func newIdentity(random io.Reader) (*Identity, error) {
	if random == nil {
		return nil, errors.New("disco: random source is required")
	}
	public, private, err := box.GenerateKey(random)
	if err != nil {
		return nil, fmt.Errorf("disco: generating identity: %w", err)
	}
	defer clear(private[:])
	if isZero(private[:]) || isZero(public[:]) {
		return nil, ErrInvalidKey
	}

	return &Identity{
		private: *private,
		public:  PublicKey{raw: *public},
	}, nil
}

// Public returns the identity's public key while the identity is active.
func (i *Identity) Public() (PublicKey, error) {
	if i == nil {
		return PublicKey{}, ErrClosed
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.isClosed {
		return PublicKey{}, ErrClosed
	}

	return i.public, nil
}

// Peer derives an authenticated channel for one control-authorized peer.
func (i *Identity) Peer(remote PublicKey) (*Peer, error) {
	if i == nil {
		return nil, ErrClosed
	}
	if remote.IsZero() {
		return nil, ErrInvalidKey
	}

	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.isClosed {
		return nil, ErrClosed
	}
	if remote == i.public {
		return nil, fmt.Errorf("%w: remote key equals local key", ErrInvalidKey)
	}
	secret, err := curve25519.X25519(i.private[:], remote.raw[:])
	if err != nil {
		return nil, fmt.Errorf("%w: unsafe remote public key", ErrInvalidKey)
	}
	clear(secret)

	peer := &Peer{
		local:  i.public,
		remote: remote,
		random: rand.Reader,
	}
	box.Precompute(&peer.shared, &remote.raw, &i.private)

	return peer, nil
}

// Close destroys the private identity material. Existing Peer channels remain
// independent and must be closed separately by their owner.
func (i *Identity) Close() {
	if i == nil {
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	clear(i.private[:])
	i.public = PublicKey{}
	i.isClosed = true
}

// Peer is one precomputed authenticated channel. It is safe for concurrent
// sealing, opening, and closure.
type Peer struct {
	mu       sync.RWMutex
	local    PublicKey
	remote   PublicKey
	shared   [keySize]byte
	random   io.Reader
	isClosed bool
}

// Close destroys the precomputed shared secret.
func (p *Peer) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.shared[:])
	p.local = PublicKey{}
	p.remote = PublicKey{}
	p.random = nil
	p.isClosed = true
}

func parseTypedKey(text string, prefix string) ([keySize]byte, error) {
	var raw [keySize]byte
	if len(text) != len(prefix)+hex.EncodedLen(keySize) ||
		text[:min(len(text), len(prefix))] != prefix {
		return raw, ErrInvalidKey
	}
	decoded, err := hex.DecodeString(text[len(prefix):])
	if err != nil || len(decoded) != keySize || isZero(decoded) ||
		prefix+hex.EncodeToString(decoded) != text {
		return raw, ErrInvalidKey
	}
	copy(raw[:], decoded)

	return raw, nil
}

func isZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}

	return true
}

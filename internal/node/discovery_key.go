package node

import "errors"

// ErrInvalidDiscoveryKey reports an absent peer-discovery public key.
var ErrInvalidDiscoveryKey = errors.New("node: invalid discovery key")

// DiscoveryKey is the public key used by clients to authenticate path discovery.
type DiscoveryKey [32]byte

// NewDiscoveryKey validates and returns a discovery public key.
func NewDiscoveryKey(value [32]byte) (DiscoveryKey, error) {
	if value == ([32]byte{}) {
		return DiscoveryKey{}, ErrInvalidDiscoveryKey
	}
	return DiscoveryKey(value), nil
}

// Bytes returns a copy of the discovery public key.
func (key DiscoveryKey) Bytes() [32]byte { return [32]byte(key) }

// IsValid reports whether the discovery public key is non-zero.
func (key DiscoveryKey) IsValid() bool { return key != DiscoveryKey{} }

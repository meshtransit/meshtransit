package node

import (
	"errors"
	"testing"
)

func TestDiscoveryKeyRejectsZeroAndReturnsCopies(t *testing.T) {
	t.Parallel()

	if _, err := NewDiscoveryKey([32]byte{}); !errors.Is(err, ErrInvalidDiscoveryKey) {
		t.Fatalf("NewDiscoveryKey(zero) error = %v, want ErrInvalidDiscoveryKey", err)
	}
	raw := [32]byte{1, 2, 3}
	key, err := NewDiscoveryKey(raw)
	if err != nil {
		t.Fatalf("NewDiscoveryKey() error = %v", err)
	}
	raw[0] = 9
	if !key.IsValid() || key.Bytes()[0] != 1 {
		t.Fatalf("DiscoveryKey = %v, want immutable non-zero key", key)
	}
}

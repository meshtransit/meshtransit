package disco

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestPublicAndNodeKeyText(t *testing.T) {
	t.Parallel()

	raw := [keySize]byte{0: 1, 1: 2, 30: 30, 31: 31}
	public, err := PublicKeyFromRaw(raw)
	if err != nil {
		t.Fatalf("PublicKeyFromRaw() error = %v", err)
	}
	parsedPublic, err := ParsePublicKey(public.String())
	if err != nil || parsedPublic != public || parsedPublic.Raw() != raw {
		t.Fatalf("ParsePublicKey() = %#v, %v", parsedPublic, err)
	}
	node, err := NodeKeyFromRaw(raw)
	if err != nil {
		t.Fatalf("NodeKeyFromRaw() error = %v", err)
	}
	parsedNode, err := ParseNodeKey(node.String())
	if err != nil || parsedNode != node || parsedNode.Raw() != raw {
		t.Fatalf("ParseNodeKey() = %#v, %v", parsedNode, err)
	}
}

func TestTypedKeysRejectNonCanonicalValues(t *testing.T) {
	t.Parallel()

	valid := publicKeyPrefix + strings.Repeat("01", keySize)
	tests := []struct {
		name  string
		value string
	}{
		{name: "empty"},
		{name: "wrong prefix", value: nodeKeyPrefix + strings.Repeat("01", keySize)},
		{name: "short", value: publicKeyPrefix + "01"},
		{name: "uppercase", value: strings.ToUpper(valid)},
		{name: "zero", value: publicKeyPrefix + strings.Repeat("00", keySize)},
		{name: "invalid hex", value: publicKeyPrefix + strings.Repeat("zz", keySize)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := ParsePublicKey(test.value); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("ParsePublicKey() error = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestIdentityLifecycle(t *testing.T) {
	t.Parallel()

	local := mustIdentity(t)
	remote := mustIdentity(t)
	remotePublic, err := remote.Public()
	if err != nil {
		t.Fatalf("remote.Public() error = %v", err)
	}
	peer, err := local.Peer(remotePublic)
	if err != nil {
		t.Fatalf("Peer() error = %v", err)
	}
	peer.Close()
	if _, err := peer.Seal(Ping{}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Seal() after Close error = %v, want ErrClosed", err)
	}

	local.Close()
	if _, err := local.Public(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Public() after Close error = %v, want ErrClosed", err)
	}
	if _, err := local.Peer(remotePublic); !errors.Is(err, ErrClosed) {
		t.Fatalf("Peer() after Close error = %v, want ErrClosed", err)
	}
}

func TestIdentityRejectsUnsafePeerKeys(t *testing.T) {
	t.Parallel()

	identity := mustIdentity(t)
	defer identity.Close()
	public, err := identity.Public()
	if err != nil {
		t.Fatalf("Public() error = %v", err)
	}
	if _, err := identity.Peer(public); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Peer(self) error = %v, want ErrInvalidKey", err)
	}
	lowOrderRaw := [keySize]byte{0: 1}
	lowOrder, err := PublicKeyFromRaw(lowOrderRaw)
	if err != nil {
		t.Fatalf("PublicKeyFromRaw() error = %v", err)
	}
	if _, err := identity.Peer(lowOrder); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Peer(low order) error = %v, want ErrInvalidKey", err)
	}
}

func TestIdentityReportsRandomFailure(t *testing.T) {
	t.Parallel()

	if _, err := newIdentity(errorReader{}); err == nil {
		t.Fatal("newIdentity() error = nil")
	}
	if _, err := newIdentity(strings.NewReader(strings.Repeat("\x00", keySize))); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("newIdentity(zero) error = %v, want ErrInvalidKey", err)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func mustIdentity(t *testing.T) *Identity {
	t.Helper()

	identity, err := NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity() error = %v", err)
	}
	t.Cleanup(identity.Close)

	return identity
}

func TestIdentityFromPrivateMatchesGenerated(t *testing.T) {
	t.Parallel()
	generated, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := IdentityFromPrivate(generated.private[:])
	if err != nil {
		t.Fatal(err)
	}
	if wrapped.public != generated.public {
		t.Fatal("wrapped key derives a different public key")
	}
	if _, err := IdentityFromPrivate(make([]byte, keySize)); err == nil {
		t.Fatal("zero key accepted")
	}
	if _, err := IdentityFromPrivate([]byte{1}); err == nil {
		t.Fatal("short key accepted")
	}
}

package disco

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

func TestNewTransactionID(t *testing.T) {
	t.Parallel()

	first, err := NewTransactionID()
	if err != nil {
		t.Fatalf("NewTransactionID() first error = %v", err)
	}
	second, err := NewTransactionID()
	if err != nil {
		t.Fatalf("NewTransactionID() second error = %v", err)
	}
	if first.IsZero() || second.IsZero() || first == second {
		t.Fatalf("NewTransactionID() returned invalid values %x and %x", first, second)
	}
	if _, err := newTransactionID(errorReader{}); err == nil {
		t.Fatal("newTransactionID(error) error = nil")
	}
	if _, err := newTransactionID(bytes.NewReader(make([]byte, transactionSize))); !errors.Is(err, ErrMalformed) {
		t.Fatalf("newTransactionID(zero) error = %v, want ErrMalformed", err)
	}
}

func TestMessageRoundTrip(t *testing.T) {
	t.Parallel()

	transactionID := TransactionID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	nodeKey := mustNodeKey(t)
	tests := []struct {
		name    string
		message Message
	}{
		{
			name: "ping",
			message: Ping{
				ID:      transactionID,
				NodeKey: nodeKey,
				Padding: 64,
			},
		},
		{
			name: "ipv4 pong",
			message: Pong{
				ID:     transactionID,
				Source: netip.MustParseAddrPort("203.0.113.20:41641"),
			},
		},
		{
			name: "ipv6 pong",
			message: Pong{
				ID:     transactionID,
				Source: netip.MustParseAddrPort("[2001:db8::20]:41641"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := marshalMessage(test.message)
			if err != nil {
				t.Fatalf("marshalMessage() error = %v", err)
			}
			decoded, err := parseMessage(encoded)
			if err != nil {
				t.Fatalf("parseMessage() error = %v", err)
			}
			if decoded != test.message {
				t.Fatalf("parseMessage() = %#v, want %#v", decoded, test.message)
			}
		})
	}
}

func TestParsePingAcceptsLegacyMessageWithoutNodeKey(t *testing.T) {
	t.Parallel()

	transactionID := TransactionID{1}
	payload := []byte{messagePing, messageVersion}
	payload = append(payload, transactionID[:]...)
	payload = append(payload, 0, 0, 0)
	decoded, err := parseMessage(payload)
	if err != nil {
		t.Fatalf("parseMessage() error = %v", err)
	}
	ping, ok := decoded.(Ping)
	if !ok || ping.ID != transactionID || !ping.NodeKey.IsZero() || ping.Padding != 3 {
		t.Fatalf("parseMessage() = %#v", decoded)
	}
}

func TestMessagesRejectMalformedValues(t *testing.T) {
	t.Parallel()

	transactionID := TransactionID{1}
	nodeKey := mustNodeKey(t)
	validPing, err := marshalMessage(Ping{ID: transactionID, NodeKey: nodeKey})
	if err != nil {
		t.Fatalf("marshalMessage() error = %v", err)
	}
	unknownVersion := bytes.Clone(validPing)
	unknownVersion[1] = 1
	unknownType := bytes.Clone(validPing)
	unknownType[0] = 0xff
	nonZeroPadding := append(bytes.Clone(validPing), 1)
	zeroTransaction := bytes.Clone(validPing)
	clear(zeroTransaction[messageHeaderSize : messageHeaderSize+transactionSize])

	tests := []struct {
		name     string
		payload  []byte
		expected error
	}{
		{name: "empty", expected: ErrMalformed},
		{name: "short header", payload: []byte{messagePing}, expected: ErrMalformed},
		{name: "unknown version", payload: unknownVersion, expected: ErrUnsupportedMessage},
		{name: "unknown type", payload: unknownType, expected: ErrUnsupportedMessage},
		{name: "nonzero padding", payload: nonZeroPadding, expected: ErrMalformed},
		{name: "zero transaction", payload: zeroTransaction, expected: ErrMalformed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := parseMessage(test.payload); !errors.Is(err, test.expected) {
				t.Fatalf("parseMessage() error = %v, want %v", err, test.expected)
			}
		})
	}

	if _, err := marshalMessage(Ping{ID: transactionID}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("marshalMessage(ping without node key) error = %v", err)
	}
	if _, err := marshalMessage(Ping{
		ID:      transactionID,
		NodeKey: nodeKey,
		Padding: maxPlaintextSize,
	}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("marshalMessage(oversized ping) error = %v", err)
	}
	if _, err := marshalMessage(Pong{
		ID:     transactionID,
		Source: netip.MustParseAddrPort("127.0.0.1:41641"),
	}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("marshalMessage(loopback pong) error = %v", err)
	}
}

func mustNodeKey(t *testing.T) NodeKey {
	t.Helper()

	raw := [keySize]byte{0: 1, 31: 2}
	key, err := NodeKeyFromRaw(raw)
	if err != nil {
		t.Fatalf("NodeKeyFromRaw() error = %v", err)
	}

	return key
}

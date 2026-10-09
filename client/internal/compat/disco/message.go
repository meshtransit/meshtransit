package disco

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
)

const (
	messageVersion = 0
	messagePing    = 0x01
	messagePong    = 0x02

	messageHeaderSize = 2
	transactionSize   = 12
	pingBaseSize      = transactionSize + keySize
	pongSize          = transactionSize + 16 + 2
)

var (
	// ErrMalformed means a packet or inner message violates the bounded wire
	// contract.
	ErrMalformed = errors.New("disco: malformed message")
	// ErrUnsupportedMessage means an authenticated peer used a message type or
	// version that this implementation does not understand.
	ErrUnsupportedMessage = errors.New("disco: unsupported message")
)

// TransactionID correlates one authenticated pong with one outstanding ping.
type TransactionID [transactionSize]byte

// NewTransactionID creates a cryptographically random transaction ID.
func NewTransactionID() (TransactionID, error) {
	return newTransactionID(rand.Reader)
}

func newTransactionID(random io.Reader) (TransactionID, error) {
	var transactionID TransactionID
	if random == nil {
		return transactionID, errors.New("disco: random source is required")
	}
	if _, err := io.ReadFull(random, transactionID[:]); err != nil {
		return TransactionID{}, fmt.Errorf("disco: generating transaction id: %w", err)
	}
	if transactionID.IsZero() {
		return TransactionID{}, ErrMalformed
	}

	return transactionID, nil
}

// IsZero reports whether a transaction ID is unset.
func (id TransactionID) IsZero() bool { return isZero(id[:]) }

// Message is one supported authenticated path-probe message.
type Message interface {
	isMessage()
}

// Ping asks a peer to prove ownership of the receiving UDP path.
type Ping struct {
	ID      TransactionID
	NodeKey NodeKey
	Padding int
}

func (Ping) isMessage() {}

// Pong proves receipt of a Ping and reports the source address observed by the
// responder.
type Pong struct {
	ID     TransactionID
	Source netip.AddrPort
}

func (Pong) isMessage() {}

func marshalMessage(message Message) ([]byte, error) {
	switch message := message.(type) {
	case Ping:
		return marshalPing(message)
	case *Ping:
		if message == nil {
			return nil, ErrMalformed
		}

		return marshalPing(*message)
	case Pong:
		return marshalPong(message)
	case *Pong:
		if message == nil {
			return nil, ErrMalformed
		}

		return marshalPong(*message)
	default:
		return nil, ErrUnsupportedMessage
	}
}

func marshalPing(message Ping) ([]byte, error) {
	if message.ID.IsZero() || message.NodeKey.IsZero() || message.Padding < 0 ||
		message.Padding > maxPlaintextSize-messageHeaderSize-pingBaseSize {
		return nil, ErrMalformed
	}
	payload := make([]byte, messageHeaderSize+pingBaseSize+message.Padding)
	payload[0] = messagePing
	payload[1] = messageVersion
	copy(payload[messageHeaderSize:], message.ID[:])
	copy(payload[messageHeaderSize+transactionSize:], message.NodeKey.raw[:])

	return payload, nil
}

func marshalPong(message Pong) ([]byte, error) {
	if message.ID.IsZero() || !validEndpoint(message.Source) {
		return nil, ErrMalformed
	}
	payload := make([]byte, messageHeaderSize+pongSize)
	payload[0] = messagePong
	payload[1] = messageVersion
	offset := messageHeaderSize
	offset += copy(payload[offset:], message.ID[:])
	address := message.Source.Addr().As16()
	offset += copy(payload[offset:], address[:])
	binary.BigEndian.PutUint16(payload[offset:], message.Source.Port())

	return payload, nil
}

func parseMessage(payload []byte) (Message, error) {
	if len(payload) < messageHeaderSize || len(payload) > maxPlaintextSize {
		return nil, ErrMalformed
	}
	if payload[1] != messageVersion {
		return nil, ErrUnsupportedMessage
	}
	switch payload[0] {
	case messagePing:
		return parsePing(payload[messageHeaderSize:])
	case messagePong:
		return parsePong(payload[messageHeaderSize:])
	default:
		return nil, ErrUnsupportedMessage
	}
}

func parsePing(payload []byte) (Message, error) {
	if len(payload) < transactionSize {
		return nil, ErrMalformed
	}
	message := Ping{}
	copy(message.ID[:], payload[:transactionSize])
	if message.ID.IsZero() {
		return nil, ErrMalformed
	}
	payload = payload[transactionSize:]
	if len(payload) >= keySize {
		var raw [keySize]byte
		copy(raw[:], payload[:keySize])
		nodeKey, err := NodeKeyFromRaw(raw)
		if err != nil {
			return nil, ErrMalformed
		}
		message.NodeKey = nodeKey
		payload = payload[keySize:]
	}
	if !isZero(payload) {
		return nil, ErrMalformed
	}
	message.Padding = len(payload)

	return message, nil
}

func parsePong(payload []byte) (Message, error) {
	if len(payload) != pongSize {
		return nil, ErrMalformed
	}
	message := Pong{}
	copy(message.ID[:], payload[:transactionSize])
	if message.ID.IsZero() {
		return nil, ErrMalformed
	}
	var rawAddress [16]byte
	copy(rawAddress[:], payload[transactionSize:transactionSize+16])
	message.Source = netip.AddrPortFrom(
		netip.AddrFrom16(rawAddress).Unmap(),
		binary.BigEndian.Uint16(payload[transactionSize+16:]),
	)
	if !validEndpoint(message.Source) {
		return nil, ErrMalformed
	}

	return message, nil
}

func validEndpoint(endpoint netip.AddrPort) bool {
	address := endpoint.Addr()

	return endpoint.IsValid() && endpoint.Port() != 0 && address.IsValid() &&
		address == address.Unmap() && !address.Is4In6() && address.Zone() == "" &&
		address.IsGlobalUnicast() && !address.IsUnspecified() &&
		!address.IsMulticast() && !address.IsLoopback() &&
		!address.IsLinkLocalUnicast()
}

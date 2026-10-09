// Package disco implements disco v2, MeshTransit's peer path discovery
// protocol (docs/protocol/disco-v2.md): authenticated PING, PONG and
// CALL_ME_MAYBE messages exchanged directly over UDP or through a relay.
//
// The package is a pure codec plus the replay guard the spec requires. It
// performs no I/O and starts no goroutines; callers own sockets and timers.
package disco

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"meshtransit.net/shared/internal/wire"
	"meshtransit.net/shared/key"
)

// Wire constants from the specification.
const (
	// Version is the plaintext version byte of disco v2.
	Version = 2
	// MaxPacketSize bounds a complete envelope (fits a 1500-byte IPv4 path).
	MaxPacketSize = 1472
	// MaxEndpoints bounds the endpoints in one CALL_ME_MAYBE.
	MaxEndpoints = 32
	// TxIDSize is the length of a transaction ID.
	TxIDSize = 12

	// maxPlaintextSize is the largest plaintext that fits MaxPacketSize after
	// the envelope header (6+32+24) and the 16-byte AEAD tag.
	maxPlaintextSize = MaxPacketSize - 6 - key.Size - 24 - 16

	endpointSize = 18
	pingBodySize = TxIDSize + key.Size + 8
	pongBodySize = TxIDSize + endpointSize + 8
	cmmFixedSize = 8 + 8 + 4 + 1
)

var (
	// ErrMalformed reports a message that violates the wire contract.
	ErrMalformed = errors.New("disco: malformed message")
	// ErrUnsupported reports an unknown version or message type.
	ErrUnsupported = errors.New("disco: unsupported version or type")
)

// MessageType identifies a plaintext message.
type MessageType uint8

// Message types defined by disco v2.
const (
	TypePing        MessageType = 0x01
	TypePong        MessageType = 0x02
	TypeCallMeMaybe MessageType = 0x03
)

// Message is one disco v2 plaintext message. The set is closed: only this
// package implements it.
type Message interface {
	Type() MessageType
	appendBody(dst []byte) ([]byte, error)
}

// TxID correlates a PONG with the PING it answers.
type TxID [TxIDSize]byte

// IsZero reports whether the ID is unset; the zero ID is invalid on the wire.
func (id TxID) IsZero() bool { return id == TxID{} }

// Ping asks a peer to prove the path it arrived on.
type Ping struct {
	TxID   TxID
	Node   key.NodePublic // sender's node key; must match the map entry of the sender's disco key
	SentAt int64          // sender clock, Unix milliseconds
	// Padding adds zero bytes for path MTU probes.
	Padding int
}

// Pong answers a Ping on the path it came from.
type Pong struct {
	TxID     TxID
	Observed netip.AddrPort // the Ping's source as seen by the responder
	Echo     int64          // the Ping's SentAt
}

// CallMeMaybe asks a peer to ping the listed endpoints now.
type CallMeMaybe struct {
	Seq       uint64 // strictly increasing per sender disco key
	SentAt    int64  // sender clock, Unix milliseconds
	NAT       NATInfo
	Flags     Flags
	Endpoints []Endpoint
}

// Type implements Message.
func (Ping) Type() MessageType { return TypePing }

// Type implements Message.
func (Pong) Type() MessageType { return TypePong }

// Type implements Message.
func (CallMeMaybe) Type() MessageType { return TypeCallMeMaybe }

// Flags carry CALL_ME_MAYBE capability bits.
type Flags uint8

// Defined flags; all other bits are reserved and must be zero.
const (
	FlagPortMapped        Flags = 1 << 0
	FlagIPv6              Flags = 1 << 1
	FlagPredictionAllowed Flags = 1 << 2

	flagsDefined = FlagPortMapped | FlagIPv6 | FlagPredictionAllowed
)

// EndpointKind says how an endpoint was learned.
type EndpointKind uint8

// Endpoint kinds.
const (
	EndpointHost            EndpointKind = 1
	EndpointServerReflex    EndpointKind = 2
	EndpointPortMapped      EndpointKind = 3
	EndpointStatic          EndpointKind = 4
	EndpointPeerReflexive   EndpointKind = 5
	endpointKindLastDefined              = EndpointPeerReflexive
)

// Endpoint is one candidate address of a node.
type Endpoint struct {
	Kind EndpointKind
	Addr netip.AddrPort
}

// MarshalPlaintext encodes a message as the plaintext of an envelope.
func MarshalPlaintext(m Message) ([]byte, error) {
	return appendPlaintext(make([]byte, 0, 64), m)
}

func appendPlaintext(dst []byte, m Message) ([]byte, error) {
	if m == nil {
		return nil, ErrMalformed
	}
	start := len(dst)
	dst = append(dst, Version, byte(m.Type()))
	dst, err := m.appendBody(dst)
	if err != nil {
		return nil, err
	}
	if len(dst)-start > maxPlaintextSize {
		return nil, fmt.Errorf("%w: plaintext exceeds %d bytes", ErrMalformed, maxPlaintextSize)
	}
	return dst, nil
}

func (p Ping) appendBody(dst []byte) ([]byte, error) {
	if p.TxID.IsZero() || p.Node.IsZero() || p.Padding < 0 || p.Padding > maxPlaintextSize {
		return nil, ErrMalformed
	}
	dst = append(dst, p.TxID[:]...)
	dst = append(dst, p.Node[:]...)
	dst, ok := wire.AppendMillis(dst, p.SentAt)
	if !ok {
		return nil, ErrMalformed
	}
	return append(dst, make([]byte, p.Padding)...), nil
}

func (p Pong) appendBody(dst []byte) ([]byte, error) {
	if p.TxID.IsZero() {
		return nil, ErrMalformed
	}
	dst = append(dst, p.TxID[:]...)
	dst, err := appendEndpointAddr(dst, p.Observed)
	if err != nil {
		return nil, err
	}
	dst, ok := wire.AppendMillis(dst, p.Echo)
	if !ok {
		return nil, ErrMalformed
	}
	return dst, nil
}

func (c CallMeMaybe) appendBody(dst []byte) ([]byte, error) {
	if len(c.Endpoints) > MaxEndpoints || c.Flags&^flagsDefined != 0 || !c.NAT.valid() {
		return nil, ErrMalformed
	}
	count, ok := wire.Len8(len(c.Endpoints))
	if !ok {
		return nil, ErrMalformed
	}
	dst = binary.BigEndian.AppendUint64(dst, c.Seq)
	if dst, ok = wire.AppendMillis(dst, c.SentAt); !ok {
		return nil, ErrMalformed
	}
	dst = append(dst, byte(c.NAT.Mapping), byte(c.NAT.Filtering), byte(c.NAT.Allocation), byte(c.Flags), count)
	for _, e := range c.Endpoints {
		if e.Kind < EndpointHost || e.Kind > endpointKindLastDefined {
			return nil, ErrMalformed
		}
		dst = append(dst, byte(e.Kind))
		var err error
		if dst, err = appendEndpointAddr(dst, e.Addr); err != nil {
			return nil, err
		}
	}
	return dst, nil
}

// ParsePlaintext decodes an envelope plaintext. It never retains plaintext:
// returned messages own their memory.
func ParsePlaintext(b []byte) (Message, error) {
	if len(b) < 2 || len(b) > maxPlaintextSize {
		return nil, ErrMalformed
	}
	if b[0] != Version {
		return nil, ErrUnsupported
	}
	body := b[2:]
	switch MessageType(b[1]) {
	case TypePing:
		return parsePing(body)
	case TypePong:
		return parsePong(body)
	case TypeCallMeMaybe:
		return parseCallMeMaybe(body)
	default:
		return nil, ErrUnsupported
	}
}

func parsePing(b []byte) (Message, error) {
	if len(b) < pingBodySize {
		return nil, ErrMalformed
	}
	var p Ping
	copy(p.TxID[:], b[:TxIDSize])
	copy(p.Node[:], b[TxIDSize:TxIDSize+key.Size])
	sentAt, ok := wire.Millis(b[TxIDSize+key.Size:])
	if !ok {
		return nil, ErrMalformed
	}
	p.SentAt = sentAt
	padding := b[pingBodySize:]
	for _, v := range padding {
		if v != 0 {
			return nil, ErrMalformed
		}
	}
	p.Padding = len(padding)
	if p.TxID.IsZero() || p.Node.IsZero() {
		return nil, ErrMalformed
	}
	return p, nil
}

func parsePong(b []byte) (Message, error) {
	if len(b) != pongBodySize {
		return nil, ErrMalformed
	}
	var p Pong
	copy(p.TxID[:], b[:TxIDSize])
	observed, err := parseEndpointAddr(b[TxIDSize : TxIDSize+endpointSize])
	if err != nil || p.TxID.IsZero() {
		return nil, ErrMalformed
	}
	p.Observed = observed
	echo, ok := wire.Millis(b[TxIDSize+endpointSize:])
	if !ok {
		return nil, ErrMalformed
	}
	p.Echo = echo
	return p, nil
}

func parseCallMeMaybe(b []byte) (Message, error) {
	if len(b) < cmmFixedSize {
		return nil, ErrMalformed
	}
	sentAt, ok := wire.Millis(b[8:16])
	if !ok {
		return nil, ErrMalformed
	}
	c := CallMeMaybe{
		Seq:    binary.BigEndian.Uint64(b[0:8]),
		SentAt: sentAt,
		NAT:    NATInfo{Mapping: Mapping(b[16]), Filtering: Filtering(b[17]), Allocation: Allocation(b[18])},
		Flags:  Flags(b[19]),
	}
	count := int(b[20])
	rest := b[cmmFixedSize:]
	if !c.NAT.valid() || c.Flags&^flagsDefined != 0 || count > MaxEndpoints || len(rest) != count*(1+endpointSize) {
		return nil, ErrMalformed
	}
	if count > 0 {
		c.Endpoints = make([]Endpoint, 0, count)
	}
	for i := range count {
		item := rest[i*(1+endpointSize) : (i+1)*(1+endpointSize)]
		kind := EndpointKind(item[0])
		if kind < EndpointHost || kind > endpointKindLastDefined {
			return nil, ErrMalformed
		}
		addr, err := parseEndpointAddr(item[1:])
		if err != nil {
			return nil, err
		}
		c.Endpoints = append(c.Endpoints, Endpoint{Kind: kind, Addr: addr})
	}
	return c, nil
}

func appendEndpointAddr(dst []byte, ap netip.AddrPort) ([]byte, error) {
	if !validEndpoint(ap) {
		return nil, fmt.Errorf("%w: endpoint", ErrMalformed)
	}
	ip16 := ap.Addr().As16()
	dst = append(dst, ip16[:]...)
	return binary.BigEndian.AppendUint16(dst, ap.Port()), nil
}

func parseEndpointAddr(b []byte) (netip.AddrPort, error) {
	if len(b) != endpointSize {
		return netip.AddrPort{}, ErrMalformed
	}
	ap := netip.AddrPortFrom(netip.AddrFrom16([16]byte(b[:16])).Unmap(), binary.BigEndian.Uint16(b[16:]))
	if !validEndpoint(ap) {
		return netip.AddrPort{}, ErrMalformed
	}
	return ap, nil
}

// validEndpoint accepts unicast addresses with a non-zero port and no zone.
func validEndpoint(ap netip.AddrPort) bool {
	a := ap.Addr()
	return ap.IsValid() && ap.Port() != 0 && a.Zone() == "" && !a.IsUnspecified() && !a.IsMulticast()
}

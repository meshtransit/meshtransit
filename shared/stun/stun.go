// Package stun is a bounded codec for the subset of STUN (RFC 8489) and its
// NAT behaviour discovery attributes (RFC 5780) that MeshTransit uses:
// Binding requests and responses with XOR-MAPPED-ADDRESS, CHANGE-REQUEST,
// RESPONSE-ORIGIN, OTHER-ADDRESS and FINGERPRINT.
//
// It performs no I/O. Parsing never panics and rejects unknown
// comprehension-required attributes, as RFC 8489 §14 requires.
package stun

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net/netip"
)

// Message types.
const (
	TypeBindingRequest  uint16 = 0x0001
	TypeBindingSuccess  uint16 = 0x0101
	TypeBindingError    uint16 = 0x0111
	magicCookie         uint32 = 0x2112A442
	headerSize                 = 20
	fingerprintXOR      uint32 = 0x5354554e
	fingerprintAttrSize        = 8

	// MaxMessageSize bounds a message we accept or produce.
	MaxMessageSize = 576
	// MaxSoftwareSize bounds the SOFTWARE attribute we send or keep.
	MaxSoftwareSize = 128
)

// Attribute types.
const (
	attrMappedAddress          uint16 = 0x0001
	attrChangeRequest          uint16 = 0x0003
	attrErrorCode              uint16 = 0x0009
	attrXORMappedAddress       uint16 = 0x0020
	attrMessageIntegrity       uint16 = 0x0008
	attrMessageIntegritySHA256 uint16 = 0x001c
	attrSoftware               uint16 = 0x8022
	attrFingerprint            uint16 = 0x8028
	attrResponseOrigin         uint16 = 0x802b
	attrOtherAddress           uint16 = 0x802c

	changeIPFlag   uint32 = 0x4
	changePortFlag uint32 = 0x2
)

var (
	// ErrNotSTUN reports a packet without a STUN header.
	ErrNotSTUN = errors.New("stun: not a STUN message")
	// ErrMalformed reports a STUN message that violates the wire format.
	ErrMalformed = errors.New("stun: malformed message")
	// ErrUnknownAttribute reports an unknown comprehension-required attribute.
	ErrUnknownAttribute = errors.New("stun: unknown comprehension-required attribute")
)

// TxID is a STUN transaction ID.
type TxID [12]byte

// Request describes a Binding request.
type Request struct {
	Change ChangeRequest
	// Software is an optional SOFTWARE attribute (RFC 8489 §14.14). Some
	// deployed servers answer only requests that carry a value they expect.
	Software string
}

// ChangeRequest asks an RFC 5780 server to answer from another address/port.
type ChangeRequest struct {
	IP, Port bool
}

// Message is a decoded Binding request or response.
type Message struct {
	Type           uint16
	TxID           TxID
	XORMapped      netip.AddrPort // response: the request's source as seen by the server
	Change         ChangeRequest  // request: RFC 5780 CHANGE-REQUEST
	ResponseOrigin netip.AddrPort // response: address the response was sent from
	OtherAddress   netip.AddrPort // response: the server's alternate address
	ErrorCode      int            // error response: class*100 + number
	Software       string         // SOFTWARE attribute, if present and ≤ MaxSoftwareSize
}

// Is reports whether b looks like a STUN message (RFC 8489 §6 demultiplexing).
func Is(b []byte) bool {
	return len(b) >= headerSize && b[0]&0xC0 == 0 && binary.BigEndian.Uint32(b[4:8]) == magicCookie
}

// AppendBindingRequest encodes a Binding request without SOFTWARE.
func AppendBindingRequest(dst []byte, id TxID, change ChangeRequest) []byte {
	out, _ := AppendRequest(dst, id, Request{Change: change}) // cannot fail without SOFTWARE

	return out
}

// AppendRequest encodes a Binding request. It fails only when Software is
// longer than MaxSoftwareSize.
func AppendRequest(dst []byte, id TxID, req Request) ([]byte, error) {
	if len(req.Software) > MaxSoftwareSize {
		return nil, ErrMalformed
	}
	change := req.Change
	start := len(dst)
	dst = appendHeader(dst, TypeBindingRequest, id)
	if req.Software != "" {
		dst = appendAttr(dst, attrSoftware, []byte(req.Software))
	}
	if change.IP || change.Port {
		var flags uint32
		if change.IP {
			flags |= changeIPFlag
		}
		if change.Port {
			flags |= changePortFlag
		}
		dst = appendAttr(dst, attrChangeRequest, binary.BigEndian.AppendUint32(nil, flags))
	}
	return finish(dst, start), nil
}

// AppendBindingSuccess encodes a Binding success response. origin and other
// are optional (zero values are omitted).
func AppendBindingSuccess(dst []byte, id TxID, mapped, origin, other netip.AddrPort) ([]byte, error) {
	if !mapped.IsValid() {
		return nil, ErrMalformed
	}
	start := len(dst)
	dst = appendHeader(dst, TypeBindingSuccess, id)
	dst = appendAttr(dst, attrXORMappedAddress, xorAddress(mapped, id))
	if origin.IsValid() {
		dst = appendAttr(dst, attrResponseOrigin, plainAddress(origin))
	}
	if other.IsValid() {
		dst = appendAttr(dst, attrOtherAddress, plainAddress(other))
	}
	return finish(dst, start), nil
}

func appendHeader(dst []byte, typ uint16, id TxID) []byte {
	dst = binary.BigEndian.AppendUint16(dst, typ)
	dst = binary.BigEndian.AppendUint16(dst, 0) // patched by finish
	dst = binary.BigEndian.AppendUint32(dst, magicCookie)
	return append(dst, id[:]...)
}

func appendAttr(dst []byte, typ uint16, value []byte) []byte {
	dst = binary.BigEndian.AppendUint16(dst, typ)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(value))) //nolint:gosec // values built here are ≤ 20 bytes
	dst = append(dst, value...)
	return append(dst, make([]byte, (4-len(value)%4)%4)...) // pad to 32 bits
}

// finish appends FINGERPRINT and patches the length field.
func finish(dst []byte, start int) []byte {
	setLength(dst[start:], len(dst)-start-headerSize+fingerprintAttrSize)
	crc := crc32.ChecksumIEEE(dst[start:]) ^ fingerprintXOR
	dst = appendAttr(dst, attrFingerprint, binary.BigEndian.AppendUint32(nil, crc))
	return dst
}

func setLength(msg []byte, n int) {
	binary.BigEndian.PutUint16(msg[2:4], uint16(n)) //nolint:gosec // messages are bounded by MaxMessageSize
}

func plainAddress(ap netip.AddrPort) []byte {
	a := ap.Addr().Unmap()
	out := make([]byte, 0, 20)
	if a.Is4() {
		ip := a.As4()
		out = append(out, 0, 0x01)
		out = binary.BigEndian.AppendUint16(out, ap.Port())
		return append(out, ip[:]...)
	}
	ip := a.As16()
	out = append(out, 0, 0x02)
	out = binary.BigEndian.AppendUint16(out, ap.Port())
	return append(out, ip[:]...)
}

func xorAddress(ap netip.AddrPort, id TxID) []byte {
	out := plainAddress(ap)
	mask := xorMask(id)
	binary.BigEndian.PutUint16(out[2:4], binary.BigEndian.Uint16(out[2:4])^uint16(magicCookie>>16))
	for i := 4; i < len(out); i++ {
		out[i] ^= mask[i-4]
	}
	return out
}

func xorMask(id TxID) [16]byte {
	var mask [16]byte
	binary.BigEndian.PutUint32(mask[:4], magicCookie)
	copy(mask[4:], id[:])
	return mask
}

// Parse decodes a Binding request, success or error response.
func Parse(b []byte) (Message, error) {
	if !Is(b) {
		return Message{}, ErrNotSTUN
	}
	length := int(binary.BigEndian.Uint16(b[2:4]))
	if len(b) > MaxMessageSize || length%4 != 0 || headerSize+length != len(b) {
		return Message{}, ErrMalformed
	}
	m := Message{Type: binary.BigEndian.Uint16(b[0:2])}
	switch m.Type {
	case TypeBindingRequest, TypeBindingSuccess, TypeBindingError:
	default:
		return Message{}, ErrMalformed
	}
	copy(m.TxID[:], b[8:20])
	sawFingerprint := false
	for rest := b[headerSize:]; len(rest) > 0; {
		if sawFingerprint || len(rest) < 4 {
			return Message{}, ErrMalformed // FINGERPRINT must be last
		}
		typ := binary.BigEndian.Uint16(rest[0:2])
		n := int(binary.BigEndian.Uint16(rest[2:4]))
		padded := (n + 3) &^ 3
		if 4+padded > len(rest) {
			return Message{}, ErrMalformed
		}
		value := rest[4 : 4+n]
		offset := len(b) - len(rest)
		if err := m.parseAttr(typ, value, b, offset); err != nil {
			return Message{}, err
		}
		if typ == attrFingerprint {
			sawFingerprint = true
		}
		rest = rest[4+padded:]
	}
	if m.Type == TypeBindingSuccess && !m.XORMapped.IsValid() {
		return Message{}, ErrMalformed
	}
	return m, nil
}

func (m *Message) parseAttr(typ uint16, value, msg []byte, offset int) error {
	var err error
	switch typ {
	case attrXORMappedAddress:
		m.XORMapped, err = parseXORAddress(value, m.TxID)
	case attrMappedAddress:
		if !m.XORMapped.IsValid() {
			m.XORMapped, err = parsePlainAddress(value)
		}
	case attrResponseOrigin:
		m.ResponseOrigin, err = parsePlainAddress(value)
	case attrOtherAddress:
		m.OtherAddress, err = parsePlainAddress(value)
	case attrChangeRequest:
		if len(value) != 4 {
			return ErrMalformed
		}
		flags := binary.BigEndian.Uint32(value)
		m.Change = ChangeRequest{IP: flags&changeIPFlag != 0, Port: flags&changePortFlag != 0}
	case attrErrorCode:
		if len(value) < 4 {
			return ErrMalformed
		}
		m.ErrorCode = int(value[2]&0x07)*100 + int(value[3])
	case attrFingerprint:
		// FINGERPRINT must be the last attribute, so the header length already
		// covers it and the CRC runs over the message bytes as received
		// (RFC 8489 §14.7).
		if len(value) != 4 || offset+fingerprintAttrSize != len(msg) {
			return ErrMalformed
		}
		if crc32.ChecksumIEEE(msg[:offset])^fingerprintXOR != binary.BigEndian.Uint32(value) {
			return ErrMalformed
		}
	case attrSoftware:
		if len(value) <= MaxSoftwareSize {
			m.Software = string(value)
		}
	case attrMessageIntegrity, attrMessageIntegritySHA256:
		// Recognised but unused: MeshTransit's STUN is unauthenticated binding.
	default:
		if typ < 0x8000 {
			return ErrUnknownAttribute
		}
	}
	return err
}

func parsePlainAddress(v []byte) (netip.AddrPort, error) {
	if len(v) < 4 || v[0] != 0 {
		return netip.AddrPort{}, ErrMalformed
	}
	port := binary.BigEndian.Uint16(v[2:4])
	switch {
	case v[1] == 0x01 && len(v) == 8:
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte(v[4:8])), port), nil
	case v[1] == 0x02 && len(v) == 20:
		return netip.AddrPortFrom(netip.AddrFrom16([16]byte(v[4:20])).Unmap(), port), nil
	default:
		return netip.AddrPort{}, ErrMalformed
	}
}

func parseXORAddress(v []byte, id TxID) (netip.AddrPort, error) {
	if len(v) != 8 && len(v) != 20 {
		return netip.AddrPort{}, ErrMalformed
	}
	var buf [20]byte
	plain := buf[:copy(buf[:], v)]
	mask := xorMask(id)
	binary.BigEndian.PutUint16(plain[2:4], binary.BigEndian.Uint16(plain[2:4])^uint16(magicCookie>>16))
	for i := 4; i < len(plain); i++ {
		plain[i] ^= mask[i-4]
	}
	return parsePlainAddress(plain)
}

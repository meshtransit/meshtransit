package mtrp

import (
	"encoding/binary"

	"meshtransit.net/shared/internal/wire"
	"meshtransit.net/shared/key"
)

// ControlType identifies a CONTROL message (mtrp-v1 §5).
type ControlType uint8

// CONTROL message types.
const (
	ControlKeepalive     ControlType = 0x01
	ControlRouteOpen     ControlType = 0x02
	ControlRouteOK       ControlType = 0x03
	ControlRouteError    ControlType = 0x04
	ControlRouteIncoming ControlType = 0x05
	ControlRouteClose    ControlType = 0x06
	ControlTicketUpdate  ControlType = 0x07
	ControlTicketAck     ControlType = 0x08
	ControlSessionClose  ControlType = 0x09
	ControlPathChallenge ControlType = 0x0A
	ControlPathResponse  ControlType = 0x0B
)

// RouteErrorCode explains a refused ROUTE_OPEN.
type RouteErrorCode uint8

// ROUTE_ERROR codes.
const (
	RouteErrorNotAuthorized RouteErrorCode = 1
	RouteErrorPeerAbsent    RouteErrorCode = 2
	RouteErrorLimit         RouteErrorCode = 3
	RouteErrorInvalid       RouteErrorCode = 4
)

// RouteCloseReason explains a closed route.
type RouteCloseReason uint8

// ROUTE_CLOSE reasons.
const (
	RouteClosePeerLeft RouteCloseReason = 1
	RouteCloseRevoked  RouteCloseReason = 2
	RouteCloseExpired  RouteCloseReason = 3
	RouteCloseByClient RouteCloseReason = 4
)

// SessionCloseReason explains a closed session.
type SessionCloseReason uint8

// SESSION_CLOSE reasons.
const (
	SessionCloseExpired  SessionCloseReason = 1
	SessionCloseRevoked  SessionCloseReason = 2
	SessionCloseDraining SessionCloseReason = 3
	SessionClosePolicy   SessionCloseReason = 4
	SessionCloseIdle     SessionCloseReason = 5
)

// ControlMessage is a decoded CONTROL plaintext. Exactly the fields of Type
// are meaningful; Ticket aliases the parsed buffer.
type ControlMessage struct {
	Type         ControlType
	Request      uint32
	Route        uint32
	Peer         key.NodePublic
	RouteError   RouteErrorCode
	RouteClose   RouteCloseReason
	SessionClose SessionCloseReason
	RetryAfterMS uint32
	NotAfterMS   uint64
	Nonce        uint64 // PATH_CHALLENGE and PATH_RESPONSE
	Ticket       []byte
}

// AppendControlMessage encodes m as a CONTROL plaintext.
func AppendControlMessage(dst []byte, m ControlMessage) ([]byte, error) {
	start := len(dst)
	dst = append(dst, byte(m.Type))
	switch m.Type {
	case ControlKeepalive:
	case ControlRouteOpen:
		if m.Request == 0 || m.Peer.IsZero() {
			return nil, ErrMalformed
		}
		dst = binary.BigEndian.AppendUint32(dst, m.Request)
		dst = append(dst, m.Peer[:]...)
	case ControlRouteOK:
		if m.Request == 0 || m.Route == 0 {
			return nil, ErrMalformed
		}
		dst = binary.BigEndian.AppendUint32(dst, m.Request)
		dst = binary.BigEndian.AppendUint32(dst, m.Route)
	case ControlRouteError:
		if m.Request == 0 || m.RouteError < RouteErrorNotAuthorized || m.RouteError > RouteErrorInvalid {
			return nil, ErrMalformed
		}
		dst = binary.BigEndian.AppendUint32(dst, m.Request)
		dst = append(dst, byte(m.RouteError))
	case ControlRouteIncoming:
		if m.Route == 0 || m.Peer.IsZero() {
			return nil, ErrMalformed
		}
		dst = binary.BigEndian.AppendUint32(dst, m.Route)
		dst = append(dst, m.Peer[:]...)
	case ControlRouteClose:
		if m.Route == 0 || m.RouteClose < RouteClosePeerLeft || m.RouteClose > RouteCloseByClient {
			return nil, ErrMalformed
		}
		dst = binary.BigEndian.AppendUint32(dst, m.Route)
		dst = append(dst, byte(m.RouteClose))
	case ControlTicketUpdate:
		n, ok := wire.Len16(len(m.Ticket))
		if !ok || n == 0 || n > MaxTicketSize {
			return nil, ErrMalformed
		}
		dst = binary.BigEndian.AppendUint16(dst, n)
		dst = append(dst, m.Ticket...)
	case ControlTicketAck:
		dst = binary.BigEndian.AppendUint64(dst, m.NotAfterMS)
	case ControlSessionClose:
		if m.SessionClose < SessionCloseExpired || m.SessionClose > SessionCloseIdle {
			return nil, ErrMalformed
		}
		dst = append(dst, byte(m.SessionClose))
		dst = binary.BigEndian.AppendUint32(dst, m.RetryAfterMS)
	case ControlPathChallenge, ControlPathResponse:
		dst = binary.BigEndian.AppendUint64(dst, m.Nonce)
	default:
		return nil, ErrUnsupported
	}
	if len(dst)-start > MaxControlPlaintext {
		return nil, ErrMalformed
	}
	return dst, nil
}

// ParseControlMessage decodes a CONTROL plaintext. Every message has an exact
// length; trailing bytes are rejected.
func ParseControlMessage(b []byte) (ControlMessage, error) {
	if len(b) == 0 || len(b) > MaxControlPlaintext {
		return ControlMessage{}, ErrMalformed
	}
	m := ControlMessage{Type: ControlType(b[0])}
	body := b[1:]
	exact := func(n int) bool { return len(body) == n }
	switch m.Type {
	case ControlKeepalive:
		if !exact(0) {
			return ControlMessage{}, ErrMalformed
		}
	case ControlRouteOpen, ControlRouteIncoming:
		if !exact(4 + key.Size) {
			return ControlMessage{}, ErrMalformed
		}
		id := binary.BigEndian.Uint32(body[:4])
		copy(m.Peer[:], body[4:])
		if m.Type == ControlRouteOpen {
			m.Request = id
		} else {
			m.Route = id
		}
		if id == 0 || m.Peer.IsZero() {
			return ControlMessage{}, ErrMalformed
		}
	case ControlRouteOK:
		if !exact(8) {
			return ControlMessage{}, ErrMalformed
		}
		m.Request, m.Route = binary.BigEndian.Uint32(body[:4]), binary.BigEndian.Uint32(body[4:])
		if m.Request == 0 || m.Route == 0 {
			return ControlMessage{}, ErrMalformed
		}
	case ControlRouteError:
		if !exact(5) {
			return ControlMessage{}, ErrMalformed
		}
		m.Request, m.RouteError = binary.BigEndian.Uint32(body[:4]), RouteErrorCode(body[4])
		if m.Request == 0 || m.RouteError < RouteErrorNotAuthorized || m.RouteError > RouteErrorInvalid {
			return ControlMessage{}, ErrMalformed
		}
	case ControlRouteClose:
		if !exact(5) {
			return ControlMessage{}, ErrMalformed
		}
		m.Route, m.RouteClose = binary.BigEndian.Uint32(body[:4]), RouteCloseReason(body[4])
		if m.Route == 0 || m.RouteClose < RouteClosePeerLeft || m.RouteClose > RouteCloseByClient {
			return ControlMessage{}, ErrMalformed
		}
	case ControlTicketUpdate:
		if len(body) < 2 {
			return ControlMessage{}, ErrMalformed
		}
		n := int(binary.BigEndian.Uint16(body[:2]))
		if n == 0 || n > MaxTicketSize || len(body) != 2+n {
			return ControlMessage{}, ErrMalformed
		}
		m.Ticket = body[2:]
	case ControlTicketAck:
		if !exact(8) {
			return ControlMessage{}, ErrMalformed
		}
		m.NotAfterMS = binary.BigEndian.Uint64(body)
	case ControlPathChallenge, ControlPathResponse:
		if !exact(8) {
			return ControlMessage{}, ErrMalformed
		}
		m.Nonce = binary.BigEndian.Uint64(body)
	case ControlSessionClose:
		if !exact(5) {
			return ControlMessage{}, ErrMalformed
		}
		m.SessionClose, m.RetryAfterMS = SessionCloseReason(body[0]), binary.BigEndian.Uint32(body[1:])
		if m.SessionClose < SessionCloseExpired || m.SessionClose > SessionCloseIdle {
			return ControlMessage{}, ErrMalformed
		}
	default:
		return ControlMessage{}, ErrUnsupported
	}
	return m, nil
}

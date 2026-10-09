package mtrp

import (
	"encoding/binary"
	"time"

	"meshtransit.net/shared/internal/wire"
)

// Handshake payload constants (mtrp-v1 §4).
const (
	// CapWebSocket says the client can fall back to WebSocket.
	CapWebSocket uint32 = 1 << 0
	capsDefined         = CapWebSocket

	// MinUDPInit is the minimum INIT size on UDP; ClientHello padding makes
	// every INIT at least this large, so no reply is larger than its request.
	MinUDPInit = 256

	clientHelloFixed = 8 + 2 + 4
	serverHelloSize  = 2 + 2 + 2 + 8
	// MaxClientHello bounds the ClientHello plaintext.
	MaxClientHello = clientHelloFixed + MaxTicketSize + MinUDPInit
)

// ClientHello is the payload of INIT.
type ClientHello struct {
	TimestampMS int64  // strictly increasing per disco key
	Ticket      []byte // signed MTRP ticket; aliases the parsed buffer
	Caps        uint32
}

// ServerHello is the payload of RESPONSE.
type ServerHello struct {
	KeepaliveS   uint16
	IdleTimeoutS uint16
	MaxRoutes    uint16
	NotAfterMS   int64
}

// NotAfter returns the ticket expiry the relay enforces.
func (h ServerHello) NotAfter() time.Time { return time.UnixMilli(h.NotAfterMS) }

// Keepalive and IdleTimeout return the session timers.
func (h ServerHello) Keepalive() time.Duration { return time.Duration(h.KeepaliveS) * time.Second }

// IdleTimeout returns how long the relay keeps a silent session.
func (h ServerHello) IdleTimeout() time.Duration {
	return time.Duration(h.IdleTimeoutS) * time.Second
}

// appendClientHello encodes h, padded with zeros to at least padTo bytes.
func appendClientHello(dst []byte, h ClientHello, padTo int) ([]byte, error) {
	n, ok := wire.Len16(len(h.Ticket))
	if !ok || n == 0 || n > MaxTicketSize || h.Caps&^capsDefined != 0 {
		return nil, ErrMalformed
	}
	start := len(dst)
	dst, ok = wire.AppendMillis(dst, h.TimestampMS)
	if !ok {
		return nil, ErrMalformed
	}
	dst = binary.BigEndian.AppendUint16(dst, n)
	dst = append(dst, h.Ticket...)
	dst = binary.BigEndian.AppendUint32(dst, h.Caps)
	if pad := padTo - (len(dst) - start); pad > 0 {
		dst = append(dst, make([]byte, pad)...)
	}
	return dst, nil
}

// parseClientHello decodes a ClientHello. Padding must be zero.
func parseClientHello(b []byte) (ClientHello, error) {
	if len(b) < clientHelloFixed+1 || len(b) > MaxClientHello {
		return ClientHello{}, ErrMalformed
	}
	ts, ok := wire.Millis(b[:8])
	if !ok {
		return ClientHello{}, ErrMalformed
	}
	n := int(binary.BigEndian.Uint16(b[8:10]))
	if n == 0 || n > MaxTicketSize || len(b) < clientHelloFixed+n {
		return ClientHello{}, ErrMalformed
	}
	h := ClientHello{TimestampMS: ts, Ticket: b[10 : 10+n], Caps: binary.BigEndian.Uint32(b[10+n : 14+n])}
	if h.Caps&^capsDefined != 0 {
		return ClientHello{}, ErrMalformed
	}
	for _, p := range b[14+n:] {
		if p != 0 {
			return ClientHello{}, ErrMalformed
		}
	}
	return h, nil
}

func appendServerHello(dst []byte, h ServerHello) ([]byte, error) {
	if h.KeepaliveS == 0 || h.IdleTimeoutS <= h.KeepaliveS || h.MaxRoutes == 0 {
		return nil, ErrMalformed
	}
	dst = binary.BigEndian.AppendUint16(dst, h.KeepaliveS)
	dst = binary.BigEndian.AppendUint16(dst, h.IdleTimeoutS)
	dst = binary.BigEndian.AppendUint16(dst, h.MaxRoutes)
	dst, ok := wire.AppendMillis(dst, h.NotAfterMS)
	if !ok {
		return nil, ErrMalformed
	}
	return dst, nil
}

func parseServerHello(b []byte) (ServerHello, error) {
	if len(b) != serverHelloSize {
		return ServerHello{}, ErrMalformed
	}
	h := ServerHello{
		KeepaliveS:   binary.BigEndian.Uint16(b[0:2]),
		IdleTimeoutS: binary.BigEndian.Uint16(b[2:4]),
		MaxRoutes:    binary.BigEndian.Uint16(b[4:6]),
	}
	var ok bool
	if h.NotAfterMS, ok = wire.Millis(b[6:14]); !ok || h.KeepaliveS == 0 || h.IdleTimeoutS <= h.KeepaliveS || h.MaxRoutes == 0 {
		return ServerHello{}, ErrMalformed
	}
	return h, nil
}

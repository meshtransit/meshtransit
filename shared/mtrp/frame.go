// Package mtrp implements the wire formats of MTRP v1, the MeshTransit Relay
// Protocol used by Interchange (docs/protocol/mtrp-v1.md): frames, CONTROL
// messages, relay tickets, handshake DoS MACs and the anti-replay window.
//
// Parsing functions never allocate on the DATA path and return slices that
// alias the input buffer; callers must copy anything they keep after reusing
// the buffer. The package performs no I/O and starts no goroutines.
package mtrp

import (
	"encoding/binary"
	"errors"
)

// Wire constants.
const (
	// Version is the frame header version.
	Version = 1
	// HeaderSize is the size of the common frame header.
	HeaderSize = 4
	// MACSize is the size of mac1, mac2 and cookies.
	MACSize = 16
	// MaxUDPFrame bounds a frame carried in one UDP datagram.
	MaxUDPFrame = 2048
	// MaxStreamFrame bounds a frame carried on TLS or WebSocket.
	MaxStreamFrame = 4096
	// MaxDataPayload bounds the payload of one DATA frame.
	MaxDataPayload = MaxUDPFrame - HeaderSize - 8
	// MaxControlPlaintext bounds a decrypted CONTROL message.
	MaxControlPlaintext = 1024

	// Minimum Noise message sizes for IK: msg1 = e(32) + enc(s)(48) + tag(16); msg2 = e(32) + tag(16).
	minNoiseInit     = 32 + 48 + 16
	minNoiseResponse = 32 + 16
	controlTagSize   = 16
	cookieNonceSize  = 24
	encCookieSize    = MACSize + 16
)

// Type is a frame type.
type Type uint8

// Frame types.
const (
	TypeInit     Type = 0x01
	TypeResponse Type = 0x02
	TypeCookie   Type = 0x03
	TypeControl  Type = 0x04
	TypeData     Type = 0x05
)

var (
	// ErrMalformed reports a frame that violates the wire contract.
	ErrMalformed = errors.New("mtrp: malformed frame")
	// ErrUnsupported reports an unknown version or frame type.
	ErrUnsupported = errors.New("mtrp: unsupported version or type")
)

// PeekType validates the common header and returns the frame type.
func PeekType(b []byte) (Type, error) {
	if len(b) < HeaderSize || len(b) > MaxStreamFrame {
		return 0, ErrMalformed
	}
	if b[0] != Version || b[2] != 0 || b[3] != 0 {
		return 0, ErrUnsupported
	}
	t := Type(b[1])
	if t < TypeInit || t > TypeData {
		return 0, ErrUnsupported
	}
	return t, nil
}

func appendHeader(dst []byte, t Type) []byte { return append(dst, Version, byte(t), 0, 0) }

// Init is the handshake initiation. Noise aliases the parsed buffer.
type Init struct {
	SenderIndex uint32
	Noise       []byte
	MAC1, MAC2  [MACSize]byte
}

// Response is the handshake response. Noise aliases the parsed buffer.
type Response struct {
	SenderIndex, ReceiverIndex uint32
	Noise                      []byte
	MAC1, MAC2                 [MACSize]byte
}

// Cookie is a cookie reply sent under load instead of a Response.
type Cookie struct {
	ReceiverIndex   uint32
	Nonce           [cookieNonceSize]byte
	EncryptedCookie [encCookieSize]byte
}

// Control is an encrypted CONTROL frame. Ciphertext aliases the parsed buffer.
type Control struct {
	ReceiverIndex uint32
	Counter       uint64
	Ciphertext    []byte
}

// Data is a DATA frame. Payload aliases the parsed buffer.
type Data struct {
	ReceiverIndex, Route uint32
	Payload              []byte
}

// AppendInitWithoutMACs appends an INIT frame up to (excluding) mac1. The
// caller computes the MACs over the returned bytes and appends them with
// AppendMACs, which keeps MAC input and frame layout in one place.
func AppendInitWithoutMACs(dst []byte, sender uint32, noise []byte) ([]byte, error) {
	if sender == 0 || len(noise) < minNoiseInit || HeaderSize+4+len(noise)+2*MACSize > MaxUDPFrame {
		return nil, ErrMalformed
	}
	dst = appendHeader(dst, TypeInit)
	dst = binary.BigEndian.AppendUint32(dst, sender)
	return append(dst, noise...), nil
}

// AppendResponseWithoutMACs appends a RESPONSE frame up to (excluding) mac1.
func AppendResponseWithoutMACs(dst []byte, sender, receiver uint32, noise []byte) ([]byte, error) {
	if sender == 0 || receiver == 0 || len(noise) < minNoiseResponse ||
		HeaderSize+8+len(noise)+2*MACSize > MaxUDPFrame {
		return nil, ErrMalformed
	}
	dst = appendHeader(dst, TypeResponse)
	dst = binary.BigEndian.AppendUint32(dst, sender)
	dst = binary.BigEndian.AppendUint32(dst, receiver)
	return append(dst, noise...), nil
}

// AppendMACs appends mac1 and mac2 to a handshake frame.
func AppendMACs(dst []byte, mac1, mac2 [MACSize]byte) []byte {
	dst = append(dst, mac1[:]...)
	return append(dst, mac2[:]...)
}

// ParseInit parses an INIT frame.
func ParseInit(b []byte) (Init, error) {
	if t, err := PeekType(b); err != nil || t != TypeInit {
		return Init{}, errorOr(err)
	}
	if len(b) < HeaderSize+4+minNoiseInit+2*MACSize || len(b) > MaxUDPFrame {
		return Init{}, ErrMalformed
	}
	m := Init{SenderIndex: binary.BigEndian.Uint32(b[4:8])}
	if m.SenderIndex == 0 {
		return Init{}, ErrMalformed
	}
	end := len(b) - 2*MACSize
	m.Noise = b[8:end]
	copy(m.MAC1[:], b[end:end+MACSize])
	copy(m.MAC2[:], b[end+MACSize:])
	return m, nil
}

// ParseResponse parses a RESPONSE frame.
func ParseResponse(b []byte) (Response, error) {
	if t, err := PeekType(b); err != nil || t != TypeResponse {
		return Response{}, errorOr(err)
	}
	if len(b) < HeaderSize+8+minNoiseResponse+2*MACSize || len(b) > MaxUDPFrame {
		return Response{}, ErrMalformed
	}
	m := Response{SenderIndex: binary.BigEndian.Uint32(b[4:8]), ReceiverIndex: binary.BigEndian.Uint32(b[8:12])}
	if m.SenderIndex == 0 || m.ReceiverIndex == 0 {
		return Response{}, ErrMalformed
	}
	end := len(b) - 2*MACSize
	m.Noise = b[12:end]
	copy(m.MAC1[:], b[end:end+MACSize])
	copy(m.MAC2[:], b[end+MACSize:])
	return m, nil
}

// MACInput returns the bytes covered by mac1 and by mac2 for a handshake frame.
func MACInput(frame []byte) (beforeMAC1, beforeMAC2 []byte, err error) {
	if len(frame) < HeaderSize+2*MACSize {
		return nil, nil, ErrMalformed
	}
	return frame[:len(frame)-2*MACSize], frame[:len(frame)-MACSize], nil
}

// AppendCookie appends a COOKIE frame (64 bytes, smaller than any INIT).
func AppendCookie(dst []byte, c Cookie) ([]byte, error) {
	if c.ReceiverIndex == 0 {
		return nil, ErrMalformed
	}
	dst = appendHeader(dst, TypeCookie)
	dst = binary.BigEndian.AppendUint32(dst, c.ReceiverIndex)
	dst = append(dst, c.Nonce[:]...)
	return append(dst, c.EncryptedCookie[:]...), nil
}

// ParseCookie parses a COOKIE frame.
func ParseCookie(b []byte) (Cookie, error) {
	if t, err := PeekType(b); err != nil || t != TypeCookie {
		return Cookie{}, errorOr(err)
	}
	if len(b) != HeaderSize+4+cookieNonceSize+encCookieSize {
		return Cookie{}, ErrMalformed
	}
	c := Cookie{ReceiverIndex: binary.BigEndian.Uint32(b[4:8])}
	if c.ReceiverIndex == 0 {
		return Cookie{}, ErrMalformed
	}
	copy(c.Nonce[:], b[8:8+cookieNonceSize])
	copy(c.EncryptedCookie[:], b[8+cookieNonceSize:])
	return c, nil
}

// AppendControlHeader appends the CONTROL header (header, receiver, counter);
// the caller appends the AEAD ciphertext, using these bytes as associated data.
func AppendControlHeader(dst []byte, receiver uint32, counter uint64) ([]byte, error) {
	if receiver == 0 {
		return nil, ErrMalformed
	}
	dst = appendHeader(dst, TypeControl)
	dst = binary.BigEndian.AppendUint32(dst, receiver)
	return binary.BigEndian.AppendUint64(dst, counter), nil
}

// ControlHeaderSize is the size of the associated data of a CONTROL frame.
const ControlHeaderSize = HeaderSize + 4 + 8

// ParseControl parses a CONTROL frame.
func ParseControl(b []byte) (Control, error) {
	if t, err := PeekType(b); err != nil || t != TypeControl {
		return Control{}, errorOr(err)
	}
	if len(b) < ControlHeaderSize+controlTagSize+1 || len(b) > ControlHeaderSize+MaxControlPlaintext+controlTagSize {
		return Control{}, ErrMalformed
	}
	c := Control{ReceiverIndex: binary.BigEndian.Uint32(b[4:8]), Counter: binary.BigEndian.Uint64(b[8:16])}
	if c.ReceiverIndex == 0 {
		return Control{}, ErrMalformed
	}
	c.Ciphertext = b[ControlHeaderSize:]
	return c, nil
}

// AppendData appends a DATA frame without allocating when dst has capacity.
func AppendData(dst []byte, receiver, route uint32, payload []byte) ([]byte, error) {
	if receiver == 0 || route == 0 || len(payload) == 0 || len(payload) > MaxDataPayload {
		return nil, ErrMalformed
	}
	dst = appendHeader(dst, TypeData)
	dst = binary.BigEndian.AppendUint32(dst, receiver)
	dst = binary.BigEndian.AppendUint32(dst, route)
	return append(dst, payload...), nil
}

// ParseData parses a DATA frame without allocating.
func ParseData(b []byte) (Data, error) {
	if t, err := PeekType(b); err != nil || t != TypeData {
		return Data{}, errorOr(err)
	}
	if len(b) < HeaderSize+9 || len(b) > HeaderSize+8+MaxDataPayload {
		return Data{}, ErrMalformed
	}
	d := Data{ReceiverIndex: binary.BigEndian.Uint32(b[4:8]), Route: binary.BigEndian.Uint32(b[8:12]), Payload: b[12:]}
	if d.ReceiverIndex == 0 || d.Route == 0 {
		return Data{}, ErrMalformed
	}
	return d, nil
}

func errorOr(err error) error {
	if err != nil {
		return err
	}
	return ErrMalformed
}

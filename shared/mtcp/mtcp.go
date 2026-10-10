// Package mtcp implements MTCP v1, the MeshTransit Control Protocol
// (docs/protocol/mtcp-v1.md): records, the Noise IK handshake between a
// node's machine key and a Core control key, the encrypted session, message
// fragmentation with bounded zstd, proofs of possession and control key
// fingerprints. Message schemas are the generated types of api/mtcp/v1.
//
// The package is transport-neutral: it reads and writes records on any
// stream and never dials, listens or starts goroutines.
package mtcp

import "errors"

// Version is the protocol version this package implements.
const Version = 1

// Wire constants (mtcp-v1 §2–§4).
const (
	// UpgradeToken is the HTTP Upgrade token of MTCP v1.
	UpgradeToken = "mtcp/1"
	// WebSocketProtocol is the WebSocket subprotocol of the fallback.
	WebSocketProtocol = "mtcp.v1"
	// UpgradePath, WebSocketPath and KeyPath are the control host paths.
	UpgradePath   = "/mtcp/v1"
	WebSocketPath = "/mtcp/v1/ws"
	KeyPath       = "/mtcp/v1/key"
	// HeaderKey names the control key ID the node chose; HeaderHandshake
	// carries a base64url handshake record.
	HeaderKey       = "MTCP-Key"
	HeaderHandshake = "MTCP-Handshake"

	// MaxRecord is the largest record body (type and payload).
	MaxRecord = 65535
	// MaxHandshakeRecord bounds INIT and RESPONSE.
	MaxHandshakeRecord = 2048
	// tagSize is the Noise ChaChaPoly authentication tag.
	tagSize = 16
	// MaxTransportPlaintext is the largest fragment one TRANSPORT record holds.
	MaxTransportPlaintext = MaxRecord - 1 - tagSize
	// fragmentHeader is msg_type and flags.
	fragmentHeader = 2
	// MaxFragmentPayload is the largest message payload per fragment.
	MaxFragmentPayload = MaxTransportPlaintext - fragmentHeader
	// MaxRecordsPerDirection ends a session (mtcp-v1 §4.3).
	MaxRecordsPerDirection = 1 << 32
)

// noisePrologue binds both sides to MTCP v1 (keys.md domain registry).
const noisePrologue = "MeshTransit MTCP v1"

// RecordType is the type byte of a record.
type RecordType uint8

// Record types.
const (
	RecordInit      RecordType = 0x01
	RecordResponse  RecordType = 0x02
	RecordTransport RecordType = 0x03
)

var (
	// ErrMalformed reports bytes that do not follow the wire format.
	ErrMalformed = errors.New("mtcp: malformed")
	// ErrTooLarge reports a record or message beyond its limit.
	ErrTooLarge = errors.New("mtcp: exceeds limit")
	// ErrHandshake reports a handshake that failed authentication.
	ErrHandshake = errors.New("mtcp: handshake failed")
	// ErrAuth reports a transport record that failed authentication.
	ErrAuth = errors.New("mtcp: record authentication failed")
	// ErrRekey reports a session that used up its records (mtcp-v1 §4.3).
	ErrRekey = errors.New("mtcp: session record limit reached")
	// ErrDirection reports a message sent in the wrong direction.
	ErrDirection = errors.New("mtcp: message in the wrong direction")
	// ErrUnsupported reports an unknown message type.
	ErrUnsupported = errors.New("mtcp: unsupported message type")
)

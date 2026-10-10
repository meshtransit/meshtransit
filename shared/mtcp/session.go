package mtcp

import (
	"sync"

	"github.com/flynn/noise"
)

// Session holds the transport keys of an established handshake. Records use
// the implicit Noise nonce, so the stream cannot be reordered, dropped or
// replayed without detection; any failure ends the session.
//
// Seal and Open are each safe for concurrent use; a record stream has one
// writer and one reader.
type Session struct {
	hash [32]byte

	sendMu sync.Mutex
	send   *noise.CipherState
	sent   uint64

	receiveMu sync.Mutex
	receive   *noise.CipherState
	received  uint64
}

func newSession(send, receive *noise.CipherState, hash []byte) *Session {
	s := &Session{send: send, receive: receive}
	copy(s.hash[:], hash)
	return s
}

// HandshakeHash returns the Noise handshake hash, unique to this session. It
// is the channel binding of proofs of possession (mtcp-v1 §6.4).
func (s *Session) HandshakeHash() [32]byte { return s.hash }

// Seal appends the TRANSPORT record body carrying plaintext (one fragment)
// to dst.
func (s *Session) Seal(dst, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > MaxTransportPlaintext {
		return nil, ErrTooLarge
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.send == nil || s.sent >= MaxRecordsPerDirection {
		return nil, ErrRekey
	}
	out, err := s.send.Encrypt(dst, nil, plaintext)
	if err != nil {
		s.send = nil
		return nil, ErrRekey
	}
	s.sent++
	return out, nil
}

// Open authenticates a TRANSPORT record body and appends its plaintext to
// dst. After a failure the session can no longer receive.
func (s *Session) Open(dst, body []byte) ([]byte, error) {
	if len(body) <= tagSize || len(body) > MaxRecord-1 {
		return nil, ErrMalformed
	}
	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	if s.receive == nil || s.received >= MaxRecordsPerDirection {
		return nil, ErrRekey
	}
	out, err := s.receive.Decrypt(dst, nil, body)
	if err != nil {
		s.receive = nil
		return nil, ErrAuth
	}
	s.received++
	return out, nil
}

package mtrp

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/flynn/noise"
)

// MaxCounter is the first CONTROL counter that is never used: a session that
// reaches it must be re-established (mtrp-v1 §4.2).
const MaxCounter = 1 << 60

var (
	// ErrRekey reports a session that has used up its counters.
	ErrRekey = errors.New("mtrp: session counter exhausted, rekey required")
	// ErrReplay reports a CONTROL frame whose counter was already accepted or
	// is older than the anti-replay window.
	ErrReplay = errors.New("mtrp: replayed control frame")
	// ErrAuth reports a CONTROL frame that failed authentication.
	ErrAuth = errors.New("mtrp: control frame authentication failed")
	// ErrWrongSession reports a frame addressed to another session index.
	ErrWrongSession = errors.New("mtrp: frame for another session")
)

// Session holds the keys of an established MTRP session. CONTROL frames are
// sealed with explicit counters, so they survive UDP reordering; the receive
// side accepts each counter once within a 2048-counter window.
//
// A Session is safe for concurrent use.
type Session struct {
	local, remote uint32
	send, recv    noise.Cipher
	binding       [32]byte
	sendCounter   atomic.Uint64

	mu     sync.Mutex // guards window
	window ReplayWindow
}

func newSession(local, remote uint32, send, recv noise.Cipher, binding []byte) *Session {
	s := &Session{local: local, remote: remote, send: send, recv: recv}
	copy(s.binding[:], binding)
	return s
}

// LocalIndex is this side's index: frames to this session carry it.
func (s *Session) LocalIndex() uint32 { return s.local }

// RemoteIndex is the peer's index: frames this side sends carry it.
func (s *Session) RemoteIndex() uint32 { return s.remote }

// ChannelBinding returns the Noise handshake hash, unique to this session.
func (s *Session) ChannelBinding() [32]byte { return s.binding }

// SealControl appends a CONTROL frame carrying plaintext to dst.
func (s *Session) SealControl(dst, plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext) > MaxControlPlaintext {
		return nil, ErrMalformed
	}
	counter := s.sendCounter.Add(1) - 1
	if counter >= MaxCounter {
		s.sendCounter.Store(MaxCounter) // stay exhausted
		return nil, ErrRekey
	}
	start := len(dst)
	dst, err := AppendControlHeader(dst, s.remote, counter)
	if err != nil {
		return nil, err
	}
	header := dst[start:]
	return s.send.Encrypt(dst, counter, header[:len(header):len(header)], plaintext), nil
}

// OpenControl authenticates a CONTROL frame and returns its plaintext,
// appended to dst. The replay window moves only after authentication, so
// forged frames cannot disturb it.
func (s *Session) OpenControl(dst, frame []byte) ([]byte, error) {
	c, err := ParseControl(frame)
	if err != nil {
		return nil, err
	}
	if c.ReceiverIndex != s.local {
		return nil, ErrWrongSession
	}
	if c.Counter >= MaxCounter {
		return nil, ErrAuth
	}
	out, err := s.recv.Decrypt(dst, c.Counter, frame[:ControlHeaderSize], c.Ciphertext)
	if err != nil {
		return nil, ErrAuth
	}
	s.mu.Lock()
	fresh := s.window.Accept(c.Counter)
	s.mu.Unlock()
	if !fresh {
		return nil, ErrReplay
	}
	return out, nil
}

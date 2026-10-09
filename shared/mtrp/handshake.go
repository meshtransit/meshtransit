package mtrp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/flynn/noise"

	"meshtransit.net/shared/key"
)

// noisePrologue binds both sides to MTRP v1 (keys.md domain registry).
const noisePrologue = "MeshTransit MTRP v1"

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

var (
	// ErrHandshake reports a handshake message that failed authentication or
	// does not belong to this handshake.
	ErrHandshake = errors.New("mtrp: handshake failed")
	// ErrMAC reports a handshake frame whose mac1 does not verify.
	ErrMAC = errors.New("mtrp: invalid handshake mac")
)

// ClientConfig configures the client side of a handshake.
type ClientConfig struct {
	Disco  key.DiscoPrivate
	Relay  key.RelayPublic
	Hello  ClientHello
	Index  uint32         // the client's random non-zero session index
	Cookie *[MACSize]byte // last cookie from this relay, if any (mac2)
	PadUDP bool           // pad INIT to MinUDPInit (UDP transport)
	Random io.Reader      // ephemeral keys; crypto/rand when nil
}

// ClientHandshake is an INIT in flight. It is single-use and not safe for
// concurrent use.
type ClientHandshake struct {
	hs      *noise.HandshakeState
	static  []byte // copy of the disco private key, erased when done
	index   uint32
	relay   key.RelayPublic
	macs    RelayMACKeys
	initMAC [MACSize]byte
	done    bool
}

// StartClientHandshake builds an INIT frame.
func StartClientHandshake(cfg ClientConfig) (*ClientHandshake, []byte, error) {
	if cfg.Disco.IsZero() || cfg.Relay.IsZero() || cfg.Index == 0 {
		return nil, nil, ErrMalformed
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	static := cfg.Disco.ECDH().Bytes()
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite,
		Random:      random,
		Pattern:     noise.HandshakeIK,
		Initiator:   true,
		Prologue:    []byte(noisePrologue),
		StaticKeypair: noise.DHKey{
			Private: static,
			Public:  cfg.Disco.ECDH().PublicKey().Bytes(),
		},
		PeerStatic: append([]byte(nil), cfg.Relay[:]...),
	})
	if err != nil {
		clear(static)
		return nil, nil, fmt.Errorf("mtrp: handshake state: %w", err)
	}
	h := &ClientHandshake{hs: hs, static: static, index: cfg.Index, relay: cfg.Relay, macs: NewRelayMACKeys(cfg.Relay)}

	padTo := 0
	if cfg.PadUDP {
		// INIT = header(4) + index(4) + e(32) + s(48) + payload + tag(16) + macs(32).
		padTo = MinUDPInit - (HeaderSize + 4 + 32 + 48 + controlTagSize + 2*MACSize)
	}
	payload, err := appendClientHello(make([]byte, 0, 128+len(cfg.Hello.Ticket)), cfg.Hello, padTo)
	if err != nil {
		h.erase()
		return nil, nil, err
	}
	msg, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		h.erase()
		return nil, nil, fmt.Errorf("mtrp: write init: %w", err)
	}
	frame, err := AppendInitWithoutMACs(make([]byte, 0, HeaderSize+4+len(msg)+2*MACSize), cfg.Index, msg)
	if err != nil {
		h.erase()
		return nil, nil, err
	}
	h.initMAC = h.macs.MAC1(frame)
	var mac2 [MACSize]byte
	if cfg.Cookie != nil {
		mac2 = MAC2(*cfg.Cookie, append(frame[:len(frame):len(frame)], h.initMAC[:]...))
	}
	return h, AppendMACs(frame, h.initMAC, mac2), nil
}

// Index returns the client's session index.
func (h *ClientHandshake) Index() uint32 { return h.index }

// OpenCookie decrypts a COOKIE frame answering this INIT. The caller starts a
// new handshake with the cookie set.
func (h *ClientHandshake) OpenCookie(frame []byte) ([MACSize]byte, error) {
	c, err := ParseCookie(frame)
	if err != nil {
		return [MACSize]byte{}, err
	}
	if c.ReceiverIndex != h.index {
		return [MACSize]byte{}, ErrHandshake
	}
	return h.macs.OpenCookie(c, h.initMAC)
}

// Finish consumes the relay's RESPONSE and returns the session.
func (h *ClientHandshake) Finish(frame []byte) (*Session, ServerHello, error) {
	if h.done {
		return nil, ServerHello{}, ErrHandshake
	}
	r, err := ParseResponse(frame)
	if err != nil {
		return nil, ServerHello{}, err
	}
	if r.ReceiverIndex != h.index {
		return nil, ServerHello{}, ErrHandshake
	}
	beforeMAC1, _, err := MACInput(frame)
	if err != nil {
		return nil, ServerHello{}, err
	}
	if !h.macs.CheckMAC1(beforeMAC1, r.MAC1) {
		return nil, ServerHello{}, ErrMAC
	}
	payload, toRelay, fromRelay, err := h.hs.ReadMessage(nil, r.Noise)
	if err != nil || toRelay == nil || fromRelay == nil {
		return nil, ServerHello{}, ErrHandshake // the state is spent either way
	}
	hello, err := parseServerHello(payload)
	if err != nil {
		return nil, ServerHello{}, err
	}
	s := newSession(h.index, r.SenderIndex, toRelay.Cipher(), fromRelay.Cipher(), h.hs.ChannelBinding())
	h.erase()
	return s, hello, nil
}

func (h *ClientHandshake) erase() {
	clear(h.static)
	h.hs = nil
	h.done = true
}

// ServerHandshake is a decrypted INIT on the relay, before it answers.
type ServerHandshake struct {
	hs     *noise.HandshakeState
	static []byte
	remote uint32
	peer   key.DiscoPublic
	hello  ClientHello
	done   bool
}

// ReadInit decrypts an INIT. The relay MUST have checked mac1 (and mac2 when
// under load) first, so this public-key work only happens for frames that
// passed the cheap checks. The returned ClientHello aliases a new buffer.
func ReadInit(relay key.RelayPrivate, frame []byte) (*ServerHandshake, error) {
	if relay.IsZero() {
		return nil, ErrMalformed
	}
	in, err := ParseInit(frame)
	if err != nil {
		return nil, err
	}
	static := relay.ECDH().Bytes()
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: cipherSuite,
		Random:      rand.Reader,
		Pattern:     noise.HandshakeIK,
		Prologue:    []byte(noisePrologue),
		StaticKeypair: noise.DHKey{
			Private: static,
			Public:  relay.ECDH().PublicKey().Bytes(),
		},
	})
	if err != nil {
		clear(static)
		return nil, fmt.Errorf("mtrp: handshake state: %w", err)
	}
	h := &ServerHandshake{hs: hs, static: static, remote: in.SenderIndex}
	payload, _, _, err := hs.ReadMessage(nil, in.Noise)
	if err != nil {
		h.erase()
		return nil, ErrHandshake
	}
	if h.hello, err = parseClientHello(payload); err != nil {
		h.erase()
		return nil, err
	}
	copy(h.peer[:], hs.PeerStatic())
	if h.peer.IsZero() {
		h.erase()
		return nil, ErrHandshake
	}
	return h, nil
}

// Peer returns the client's disco key (the Noise initiator static key).
func (h *ServerHandshake) Peer() key.DiscoPublic { return h.peer }

// Hello returns the decrypted ClientHello.
func (h *ServerHandshake) Hello() ClientHello { return h.hello }

// RemoteIndex returns the client's session index.
func (h *ServerHandshake) RemoteIndex() uint32 { return h.remote }

// Respond builds the RESPONSE frame and the session. localIndex is the
// relay's random non-zero index for this session.
func (h *ServerHandshake) Respond(localIndex uint32, hello ServerHello, macs RelayMACKeys) ([]byte, *Session, error) {
	if h.done || localIndex == 0 {
		return nil, nil, ErrHandshake
	}
	payload, err := appendServerHello(make([]byte, 0, serverHelloSize), hello)
	if err != nil {
		return nil, nil, err
	}
	// Noise returns the initiator→responder state first on both sides.
	msg, clientToRelay, relayToClient, err := h.hs.WriteMessage(nil, payload)
	if err != nil || clientToRelay == nil || relayToClient == nil {
		h.erase()
		return nil, nil, fmt.Errorf("mtrp: write response: %w", errors.Join(ErrHandshake, err))
	}
	frame, err := AppendResponseWithoutMACs(make([]byte, 0, HeaderSize+8+len(msg)+2*MACSize), localIndex, h.remote, msg)
	if err != nil {
		h.erase()
		return nil, nil, err
	}
	s := newSession(localIndex, h.remote, relayToClient.Cipher(), clientToRelay.Cipher(), h.hs.ChannelBinding())
	h.erase()
	return AppendMACs(frame, macs.MAC1(frame), [MACSize]byte{}), s, nil
}

func (h *ServerHandshake) erase() {
	clear(h.static)
	h.hs = nil
	h.done = true
}

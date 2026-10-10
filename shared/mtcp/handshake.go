package mtcp

import (
	"crypto/rand"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/flynn/noise"
	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/shared/key"
)

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// Hello limits. They keep both handshake records under MaxHandshakeRecord.
const (
	maxCapabilities    = 32
	maxCapabilityBytes = 64
	maxClientField     = 64
	maxProfileHint     = 64
	sessionIDSize      = 16
)

var (
	marshal   = proto.MarshalOptions{Deterministic: true}
	unmarshal = proto.UnmarshalOptions{DiscardUnknown: true}
)

// ClientConfig configures the node side of a handshake.
type ClientConfig struct {
	Machine key.MachinePrivate
	Control key.ControlPublic
	Hello   *mtcpv1.ClientHello
	Random  io.Reader // ephemeral keys; crypto/rand when nil
}

// ClientHandshake is an INIT in flight. It is single-use and not safe for
// concurrent use.
type ClientHandshake struct {
	hs     *noise.HandshakeState
	static []byte
	done   bool
}

// StartClient builds the INIT record body.
func StartClient(cfg ClientConfig) (*ClientHandshake, []byte, error) {
	if cfg.Machine.IsZero() || cfg.Control.IsZero() {
		return nil, nil, ErrMalformed
	}
	if err := ValidateClientHello(cfg.Hello); err != nil {
		return nil, nil, err
	}
	payload, err := marshal.Marshal(cfg.Hello)
	if err != nil {
		return nil, nil, fmt.Errorf("mtcp: encode ClientHello: %w", err)
	}
	random := cfg.Random
	if random == nil {
		random = rand.Reader
	}
	static := cfg.Machine.ECDH().Bytes()
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        random,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      []byte(noisePrologue),
		StaticKeypair: noise.DHKey{Private: static, Public: cfg.Machine.ECDH().PublicKey().Bytes()},
		PeerStatic:    append([]byte(nil), cfg.Control[:]...),
	})
	if err != nil {
		clear(static)
		return nil, nil, fmt.Errorf("mtcp: handshake state: %w", err)
	}
	h := &ClientHandshake{hs: hs, static: static}
	init, _, _, err := hs.WriteMessage(nil, payload)
	if err != nil {
		h.erase()
		return nil, nil, fmt.Errorf("mtcp: write INIT: %w", err)
	}
	if len(init) > MaxHandshakeRecord {
		h.erase()
		return nil, nil, ErrTooLarge
	}
	return h, init, nil
}

// Finish consumes the RESPONSE record body and returns the session. A
// ServerHello with reject set is returned with the session; the caller
// reports the rejection and closes.
func (h *ClientHandshake) Finish(response []byte) (*Session, *mtcpv1.ServerHello, error) {
	if h == nil || h.done {
		return nil, nil, ErrHandshake
	}
	defer h.erase()
	if len(response) > MaxHandshakeRecord {
		return nil, nil, ErrTooLarge
	}
	payload, send, receive, err := h.hs.ReadMessage(nil, response)
	if err != nil || send == nil || receive == nil {
		return nil, nil, ErrHandshake
	}
	hello := &mtcpv1.ServerHello{}
	if err := unmarshal.Unmarshal(payload, hello); err != nil {
		return nil, nil, ErrMalformed
	}
	if err := ValidateServerHello(hello); err != nil {
		return nil, nil, err
	}
	return newSession(send, receive, h.hs.ChannelBinding()), hello, nil
}

func (h *ClientHandshake) erase() {
	clear(h.static)
	h.hs = nil
	h.done = true
}

// ServerHandshake is a decrypted INIT on Core, before it answers.
type ServerHandshake struct {
	hs      *noise.HandshakeState
	static  []byte
	machine key.MachinePublic
	hello   *mtcpv1.ClientHello
	done    bool
}

// ReadInit decrypts an INIT record body with the control key the node
// named. Core MUST have applied its admission limits first (mtcp-v1 §3).
func ReadInit(control key.ControlPrivate, init []byte, random io.Reader) (*ServerHandshake, error) {
	if control.IsZero() {
		return nil, ErrMalformed
	}
	if len(init) > MaxHandshakeRecord {
		return nil, ErrTooLarge
	}
	if random == nil {
		random = rand.Reader
	}
	static := control.ECDH().Bytes()
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        random,
		Pattern:       noise.HandshakeIK,
		Prologue:      []byte(noisePrologue),
		StaticKeypair: noise.DHKey{Private: static, Public: control.ECDH().PublicKey().Bytes()},
	})
	if err != nil {
		clear(static)
		return nil, fmt.Errorf("mtcp: handshake state: %w", err)
	}
	h := &ServerHandshake{hs: hs, static: static}
	payload, _, _, err := hs.ReadMessage(nil, init)
	if err != nil {
		h.erase()
		return nil, ErrHandshake
	}
	copy(h.machine[:], hs.PeerStatic())
	hello := &mtcpv1.ClientHello{}
	if err := unmarshal.Unmarshal(payload, hello); err != nil || h.machine.IsZero() {
		h.erase()
		return nil, ErrMalformed
	}
	if err := ValidateClientHello(hello); err != nil {
		h.erase()
		return nil, err
	}
	h.hello = hello
	return h, nil
}

// Machine returns the node's authenticated machine key.
func (h *ServerHandshake) Machine() key.MachinePublic { return h.machine }

// Hello returns the decrypted ClientHello.
func (h *ServerHandshake) Hello() *mtcpv1.ClientHello { return h.hello }

// Respond builds the RESPONSE record body and returns the session.
func (h *ServerHandshake) Respond(hello *mtcpv1.ServerHello) (*Session, []byte, error) {
	if h == nil || h.done {
		return nil, nil, ErrHandshake
	}
	defer h.erase()
	if err := ValidateServerHello(hello); err != nil {
		return nil, nil, err
	}
	payload, err := marshal.Marshal(hello)
	if err != nil {
		return nil, nil, fmt.Errorf("mtcp: encode ServerHello: %w", err)
	}
	response, receive, send, err := h.hs.WriteMessage(nil, payload)
	if err != nil || send == nil || receive == nil {
		return nil, nil, ErrHandshake
	}
	if len(response) > MaxHandshakeRecord {
		return nil, nil, ErrTooLarge
	}
	return newSession(send, receive, h.hs.ChannelBinding()), response, nil
}

func (h *ServerHandshake) erase() {
	clear(h.static)
	h.hs = nil
	h.done = true
}

// ValidateClientHello checks the bounds of a ClientHello. Policy (version
// support, timestamps, client minimums) is the receiver's decision.
func ValidateClientHello(hello *mtcpv1.ClientHello) error {
	if hello == nil || hello.GetProtocolVersion() == 0 || hello.GetTimestampMs() <= 0 ||
		(len(hello.GetNodeKey()) != 0 && len(hello.GetNodeKey()) != key.Size) ||
		len(hello.GetProfileHint()) > maxProfileHint || !validCapabilities(hello.GetCapabilities()) {
		return ErrMalformed
	}
	client := hello.GetClient()
	for _, field := range []string{client.GetProduct(), client.GetVersion(), client.GetOs(), client.GetOsVersion(),
		client.GetArch()} {
		if len(field) > maxClientField || !utf8.ValidString(field) {
			return ErrMalformed
		}
	}
	return nil
}

// ValidateServerHello checks the bounds of a ServerHello.
func ValidateServerHello(hello *mtcpv1.ServerHello) error {
	if hello == nil || hello.GetProtocolVersion() == 0 || len(hello.GetSessionId()) != sessionIDSize ||
		len(hello.GetProfileHint()) > maxProfileHint || !validCapabilities(hello.GetCapabilities()) {
		return ErrMalformed
	}
	return nil
}

func validCapabilities(capabilities []string) bool {
	if len(capabilities) > maxCapabilities {
		return false
	}
	for _, name := range capabilities {
		if name == "" || len(name) > maxCapabilityBytes || !utf8.ValidString(name) {
			return false
		}
	}
	return true
}

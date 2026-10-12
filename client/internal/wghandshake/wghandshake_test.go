package wghandshake

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

// captureBind records what a device sends and never receives anything.
type captureBind struct {
	sent   chan []byte
	closed chan struct{}
}

func (b *captureBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.closed = make(chan struct{})
	closed := b.closed
	receive := func([][]byte, []int, []conn.Endpoint) (int, error) {
		<-closed
		return 0, net.ErrClosed
	}
	return []conn.ReceiveFunc{receive}, 51820, nil
}

func (b *captureBind) Close() error {
	if b.closed != nil {
		select {
		case <-b.closed:
		default:
			close(b.closed)
		}
	}
	return nil
}
func (b *captureBind) SetMark(uint32) error { return nil }
func (b *captureBind) BatchSize() int       { return 1 }
func (b *captureBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	for _, buf := range bufs {
		select {
		case b.sent <- bytes.Clone(buf):
		default:
		}
	}
	return nil
}

func (b *captureBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: address}, nil
}

func privateKey(seed byte) [32]byte {
	var key [32]byte
	for index := range key {
		key[index] = seed + byte(index)
	}
	key[0] &= 248
	key[31] = (key[31] & 127) | 64
	return key
}

func publicKey(t testing.TB, private [32]byte) [32]byte {
	t.Helper()
	public, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	var out [32]byte
	copy(out[:], public)
	return out
}

// realInitiation makes a wireguard-go device with initiatorKey send a
// handshake initiation to responderPublic and returns it.
func realInitiation(t testing.TB, initiatorKey, responderPublic [32]byte) []byte {
	t.Helper()
	bind := &captureBind{sent: make(chan []byte, 8)}
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: device.DiscardLogf}
	initiator := device.NewDevice(tuntest.NewChannelTUN().TUN(), bind, logger)
	t.Cleanup(initiator.Close)
	configuration := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=127.0.0.1:9\nallowed_ip=10.9.0.2/32\npersistent_keepalive_interval=1\n",
		hex.EncodeToString(initiatorKey[:]), hex.EncodeToString(responderPublic[:]))
	if err := initiator.IpcSet(configuration); err != nil {
		t.Fatal(err)
	}
	if err := initiator.Up(); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for {
		select {
		case packet := <-bind.sent:
			if len(packet) == device.MessageInitiationSize && packet[0] == device.MessageInitiationType {
				return packet
			}
		case <-deadline:
			t.Fatal("wireguard-go sent no handshake initiation")
		}
	}
}

func TestInitiatorReadsARealWireGuardInitiation(t *testing.T) {
	t.Parallel()
	responderKey, initiatorKey := privateKey(0x11), privateKey(0x22)
	packet := realInitiation(t, initiatorKey, publicKey(t, responderKey))

	responder, err := NewResponder(responderKey)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := responder.Initiator(packet)
	if !ok || got != publicKey(t, initiatorKey) {
		t.Fatalf("Initiator() = %x, %t; want %x", got, ok, publicKey(t, initiatorKey))
	}
}

func TestInitiatorRejectsWhatWireGuardWouldReject(t *testing.T) {
	t.Parallel()
	responderKey, initiatorKey := privateKey(0x11), privateKey(0x22)
	packet := realInitiation(t, initiatorKey, publicKey(t, responderKey))
	responder, err := NewResponder(responderKey)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewResponder(privateKey(0x33))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := other.Initiator(packet); ok {
		t.Error("an initiation for another key was read")
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"short":          func(p []byte) []byte { return p[:len(p)-1] },
		"transport type": func(p []byte) []byte { p[0] = device.MessageTransportType; return p },
		"bad mac1":       func(p []byte) []byte { p[120] ^= 1; return p },
		"bad static":     func(p []byte) []byte { p[staticOffset] ^= 1; return p },
		"bad ephemeral":  func(p []byte) []byte { p[ephemeralOffset] ^= 1; return p },
		"zero ephemeral": func(p []byte) []byte { clear(p[ephemeralOffset:staticOffset]); return p },
	} {
		if _, ok := responder.Initiator(mutate(bytes.Clone(packet))); ok {
			t.Errorf("%s: initiation accepted", name)
		}
	}
}

// BenchmarkInitiator measures reading one valid initiation: MAC1, one
// X25519 and one AEAD open.
func BenchmarkInitiator(b *testing.B) {
	responderKey, initiatorKey := privateKey(0x11), privateKey(0x22)
	packet := realInitiation(b, initiatorKey, publicKey(b, responderKey))
	responder, err := NewResponder(responderKey)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for range b.N {
		if _, ok := responder.Initiator(packet); !ok {
			b.Fatal("initiation rejected")
		}
	}
}

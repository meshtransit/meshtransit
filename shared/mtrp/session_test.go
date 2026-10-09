package mtrp

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"meshtransit.net/shared/key"
)

type handshakePeers struct {
	disco  key.DiscoPrivate
	relay  key.RelayPrivate
	macs   RelayMACKeys
	ticket []byte
}

func newHandshakePeers(t testing.TB) handshakePeers {
	t.Helper()
	disco, err := key.NewDiscoPrivate()
	if err != nil {
		t.Fatal(err)
	}
	relay, err := key.NewRelayPrivate()
	if err != nil {
		t.Fatal(err)
	}
	ticket := sampleTicket()
	ticket.Disco = disco.Public()
	signed, err := ticket.Sign(signingKey(t))
	if err != nil {
		t.Fatal(err)
	}
	return handshakePeers{disco: disco, relay: relay, macs: NewRelayMACKeys(relay.Public()), ticket: signed}
}

func (p handshakePeers) clientConfig() ClientConfig {
	return ClientConfig{
		Disco:  p.disco,
		Relay:  p.relay.Public(),
		Hello:  ClientHello{TimestampMS: 1760000000000, Ticket: p.ticket, Caps: CapWebSocket},
		Index:  0x0a0b0c0d,
		PadUDP: true,
	}
}

var testServerHello = ServerHello{KeepaliveS: 25, IdleTimeoutS: 90, MaxRoutes: 4096, NotAfterMS: 1760000600000}

// establish runs a complete handshake and returns both sessions.
func establish(t testing.TB, p handshakePeers) (*Session, *Session) {
	t.Helper()
	client, initFrame, err := StartClientHandshake(p.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	in, err := ParseInit(initFrame)
	if err != nil {
		t.Fatal(err)
	}
	before1, _, err := MACInput(initFrame)
	if err != nil || !p.macs.CheckMAC1(before1, in.MAC1) {
		t.Fatal("INIT mac1 does not verify")
	}
	server, err := ReadInit(p.relay, initFrame)
	if err != nil {
		t.Fatalf("ReadInit: %v", err)
	}
	respFrame, relaySession, err := server.Respond(0x01020304, testServerHello, p.macs)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	clientSession, hello, err := client.Finish(respFrame)
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if hello != testServerHello {
		t.Fatalf("ServerHello = %+v", hello)
	}
	return clientSession, relaySession
}

func TestHandshake(t *testing.T) {
	t.Parallel()
	p := newHandshakePeers(t)
	client, initFrame, err := StartClientHandshake(p.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(initFrame) < MinUDPInit {
		t.Fatalf("UDP INIT is %d bytes, want ≥ %d", len(initFrame), MinUDPInit)
	}
	server, err := ReadInit(p.relay, initFrame)
	if err != nil {
		t.Fatal(err)
	}
	if !key.Equal(server.Peer(), p.disco.Public()) || server.RemoteIndex() != client.Index() ||
		!bytes.Equal(server.Hello().Ticket, p.ticket) || server.Hello().Caps != CapWebSocket {
		t.Fatalf("server view: peer %v index %d hello %+v", server.Peer(), server.RemoteIndex(), server.Hello())
	}
	respFrame, relaySession, err := server.Respond(0x01020304, testServerHello, p.macs)
	if err != nil {
		t.Fatal(err)
	}
	if len(respFrame) >= len(initFrame) {
		t.Fatalf("RESPONSE (%d) not smaller than INIT (%d)", len(respFrame), len(initFrame))
	}
	clientSession, _, err := client.Finish(respFrame)
	if err != nil {
		t.Fatal(err)
	}
	if clientSession.RemoteIndex() != relaySession.LocalIndex() || relaySession.RemoteIndex() != clientSession.LocalIndex() {
		t.Fatal("session indexes do not pair up")
	}
	if clientSession.ChannelBinding() != relaySession.ChannelBinding() {
		t.Fatal("channel bindings differ")
	}
	if _, _, err := client.Finish(respFrame); !errors.Is(err, ErrHandshake) {
		t.Fatal("handshake finished twice")
	}
	if _, _, err := server.Respond(5, testServerHello, p.macs); !errors.Is(err, ErrHandshake) {
		t.Fatal("handshake answered twice")
	}
}

func TestHandshakeRejects(t *testing.T) {
	t.Parallel()
	p := newHandshakePeers(t)

	_, initFrame, err := StartClientHandshake(p.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	other, _ := key.NewRelayPrivate()
	if _, err := ReadInit(other, initFrame); !errors.Is(err, ErrHandshake) {
		t.Fatalf("INIT for another relay accepted: %v", err)
	}
	tampered := bytes.Clone(initFrame)
	tampered[HeaderSize+4+40] ^= 1
	if _, err := ReadInit(p.relay, tampered); !errors.Is(err, ErrHandshake) {
		t.Fatalf("tampered INIT accepted: %v", err)
	}

	client, initFrame, _ := StartClientHandshake(p.clientConfig())
	server, err := ReadInit(p.relay, initFrame)
	if err != nil {
		t.Fatal(err)
	}
	respFrame, _, err := server.Respond(7, testServerHello, p.macs)
	if err != nil {
		t.Fatal(err)
	}
	badMAC := bytes.Clone(respFrame)
	badMAC[len(badMAC)-MACSize-1] ^= 1
	if _, _, err := client.Finish(badMAC); !errors.Is(err, ErrMAC) {
		t.Fatalf("RESPONSE with bad mac1: %v", err)
	}
	wrongIndex, _, _ := StartClientHandshake(p.clientConfig())
	wrongIndex.index++
	if _, _, err := wrongIndex.Finish(respFrame); !errors.Is(err, ErrHandshake) {
		t.Fatalf("RESPONSE for another index: %v", err)
	}

	if _, _, err := StartClientHandshake(ClientConfig{Relay: p.relay.Public(), Index: 1}); !errors.Is(err, ErrMalformed) {
		t.Fatal("handshake without a disco key")
	}
	bad := p.clientConfig()
	bad.Hello.Caps = 1 << 9
	if _, _, err := StartClientHandshake(bad); !errors.Is(err, ErrMalformed) {
		t.Fatal("undefined caps encoded")
	}
	if _, _, err := server.Respond(0, testServerHello, p.macs); err == nil {
		t.Fatal("zero local index accepted")
	}
}

func TestHandshakeCookie(t *testing.T) {
	t.Parallel()
	p := newHandshakePeers(t)
	client, initFrame, err := StartClientHandshake(p.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	in, _ := ParseInit(initFrame)
	cookie := [MACSize]byte{0xc0, 0x0c}
	nonce, sealed, err := p.macs.SealCookie(cookie, in.MAC1, fixedReader(7))
	if err != nil {
		t.Fatal(err)
	}
	cookieFrame, err := AppendCookie(nil, Cookie{ReceiverIndex: in.SenderIndex, Nonce: nonce, EncryptedCookie: sealed})
	if err != nil {
		t.Fatal(err)
	}
	got, err := client.OpenCookie(cookieFrame)
	if err != nil || got != cookie {
		t.Fatalf("OpenCookie = %x, %v", got, err)
	}

	cfg := p.clientConfig()
	cfg.Cookie = &got
	_, retry, err := StartClientHandshake(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r, _ := ParseInit(retry)
	_, before2, _ := MACInput(retry)
	if !CheckMAC2(cookie, before2, r.MAC2) {
		t.Fatal("mac2 with the cookie does not verify")
	}
}

func TestSessionControl(t *testing.T) {
	t.Parallel()
	clientSession, relaySession := establish(t, newHandshakePeers(t))

	frames := make([][]byte, 0, 4)
	for i := range byte(4) {
		f, err := clientSession.SealControl(nil, []byte{i + 1, 0xaa})
		if err != nil {
			t.Fatal(err)
		}
		frames = append(frames, f)
	}
	// Out of order delivery within the window is fine; each frame once.
	for _, i := range []byte{2, 0, 3, 1} {
		got, err := relaySession.OpenControl(nil, frames[i])
		if err != nil || !bytes.Equal(got, []byte{i + 1, 0xaa}) {
			t.Fatalf("frame %d: %x, %v", i, got, err)
		}
	}
	if _, err := relaySession.OpenControl(nil, frames[1]); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}

	back, err := relaySession.SealControl(nil, []byte{0x09})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := clientSession.OpenControl(nil, back); err != nil || !bytes.Equal(got, []byte{0x09}) {
		t.Fatalf("relay to client: %x, %v", got, err)
	}
	// A session cannot open its own frames (directional keys) and rejects
	// frames for another index.
	own, _ := clientSession.SealControl(nil, []byte{1})
	if _, err := clientSession.OpenControl(nil, own); !errors.Is(err, ErrWrongSession) {
		t.Fatalf("own frame: %v", err)
	}
	tampered := bytes.Clone(frames[0])
	tampered[len(tampered)-1] ^= 1
	if _, err := relaySession.OpenControl(nil, tampered); !errors.Is(err, ErrAuth) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := clientSession.SealControl(nil, nil); !errors.Is(err, ErrMalformed) {
		t.Fatal("empty control message sealed")
	}

	clientSession.sendCounter.Store(MaxCounter)
	if _, err := clientSession.SealControl(nil, []byte{1}); !errors.Is(err, ErrRekey) {
		t.Fatalf("exhausted counter: %v", err)
	}
}

func TestSessionConcurrentSeal(t *testing.T) {
	t.Parallel()
	clientSession, relaySession := establish(t, newHandshakePeers(t))
	const workers, perWorker = 8, 64
	out := make(chan []byte, workers*perWorker)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range perWorker {
				f, err := clientSession.SealControl(nil, []byte{1})
				if err != nil {
					t.Error(err)
					return
				}
				out <- f
			}
		})
	}
	wg.Wait()
	close(out)
	n := 0
	for f := range out {
		if _, err := relaySession.OpenControl(nil, f); err != nil {
			t.Fatalf("frame %d: %v", n, err)
		}
		n++
	}
	if n != workers*perWorker {
		t.Fatalf("opened %d frames", n)
	}
}

func TestHelloCodecs(t *testing.T) {
	t.Parallel()
	h := ClientHello{TimestampMS: 1, Ticket: []byte{1, 2, 3}, Caps: CapWebSocket}
	b, err := appendClientHello(nil, h, 64)
	if err != nil || len(b) != 64 {
		t.Fatalf("padded hello: %d bytes, %v", len(b), err)
	}
	got, err := parseClientHello(b)
	if err != nil || got.TimestampMS != 1 || !bytes.Equal(got.Ticket, h.Ticket) {
		t.Fatalf("parse = %+v, %v", got, err)
	}
	b[len(b)-1] = 1
	if _, err := parseClientHello(b); !errors.Is(err, ErrMalformed) {
		t.Fatal("non-zero padding accepted")
	}
	for _, bad := range []ServerHello{
		{KeepaliveS: 0, IdleTimeoutS: 90, MaxRoutes: 1},
		{KeepaliveS: 30, IdleTimeoutS: 30, MaxRoutes: 1},
		{KeepaliveS: 25, IdleTimeoutS: 90, MaxRoutes: 0},
	} {
		if _, err := appendServerHello(nil, bad); err == nil {
			t.Errorf("invalid ServerHello %+v encoded", bad)
		}
	}
	if _, err := parseServerHello(make([]byte, serverHelloSize-1)); err == nil {
		t.Fatal("short ServerHello parsed")
	}
}

func FuzzReadInit(f *testing.F) {
	p := newHandshakePeers(f)
	_, initFrame, err := StartClientHandshake(p.clientConfig())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(initFrame)
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ReadInit(p.relay, b) // must never panic
	})
}

func FuzzParseClientHello(f *testing.F) {
	b, _ := appendClientHello(nil, ClientHello{TimestampMS: 1, Ticket: []byte{1}}, 0)
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := parseClientHello(b)
		if err != nil {
			return
		}
		again, err := appendClientHello(nil, h, len(b))
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("round trip: %x -> %x, %v", b, again, err)
		}
	})
}

package disco

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"net/netip"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"meshtransit.net/shared/key"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

// vectorsPath is the committed test vector file this package must reproduce.
const vectorsPath = "testdata/vectors.json"

// fixedReader returns the same byte forever; it makes nonces reproducible.
type fixedReader byte

func (r fixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

func testKeys(t *testing.T) (a, b key.DiscoPrivate) {
	t.Helper()
	var err error
	if a, err = key.DiscoPrivateFromBytes(bytes.Repeat([]byte{0x11}, key.Size)); err != nil {
		t.Fatal(err)
	}
	if b, err = key.DiscoPrivateFromBytes(bytes.Repeat([]byte{0x22}, key.Size)); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func peerKeys(t *testing.T) (ab, ba *PeerKey) {
	t.Helper()
	a, b := testKeys(t)
	var err error
	if ab, err = NewPeerKey(a, b.Public()); err != nil {
		t.Fatal(err)
	}
	if ba, err = NewPeerKey(b, a.Public()); err != nil {
		t.Fatal(err)
	}
	return ab, ba
}

func sampleMessages() map[string]Message {
	var node key.NodePublic
	copy(node[:], bytes.Repeat([]byte{0x33}, key.Size))
	txid := TxID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	return map[string]Message{
		"ping":        Ping{TxID: txid, Node: node, SentAt: 1760000000000},
		"ping_padded": Ping{TxID: txid, Node: node, SentAt: 1760000000000, Padding: 64},
		"pong_v4":     Pong{TxID: txid, Observed: netip.MustParseAddrPort("203.0.113.7:41641"), Echo: 1760000000000},
		"pong_v6":     Pong{TxID: txid, Observed: netip.MustParseAddrPort("[2001:db8::7]:41641"), Echo: 1760000000000},
		// Through the relay a Pong observes no source (disco-v2 §3.2).
		"pong_relayed": Pong{TxID: txid, Echo: 1760000000000},
		"call_me_maybe": CallMeMaybe{
			Seq: 7, SentAt: 1760000000000,
			NAT:   NATInfo{Mapping: MappingAddressAndPortDependent, Filtering: FilteringAddressAndPortDependent, Allocation: AllocationSequential},
			Flags: FlagIPv6 | FlagPredictionAllowed,
			Endpoints: []Endpoint{
				{Kind: EndpointHost, Addr: netip.MustParseAddrPort("192.168.1.20:41641")},
				{Kind: EndpointServerReflex, Addr: netip.MustParseAddrPort("198.51.100.4:50123")},
				{Kind: EndpointHost, Addr: netip.MustParseAddrPort("[2001:db8::20]:41641")},
			},
		},
		"call_me_maybe_empty": CallMeMaybe{Seq: 1, SentAt: 1760000000000},
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	t.Parallel()
	ab, ba := peerKeys(t)
	for name, m := range sampleMessages() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			packet, err := ab.Seal(nil, m, fixedReader(0x5a))
			if err != nil {
				t.Fatal(err)
			}
			if !LooksLikeDisco(packet) {
				t.Fatal("sealed packet not recognised")
			}
			got, err := ba.Open(packet)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !reflect.DeepEqual(got, m) {
				t.Fatalf("got %#v, want %#v", got, m)
			}
			// The same key opens in the reverse direction.
			back, err := ba.Seal(nil, m, fixedReader(0x5b))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ab.Open(back); err != nil {
				t.Fatalf("reverse Open: %v", err)
			}
		})
	}
}

func TestPongIsNeverLargerThanPing(t *testing.T) {
	t.Parallel()
	ab, _ := peerKeys(t)
	msgs := sampleMessages()
	ping, _ := ab.Seal(nil, msgs["ping"], fixedReader(1))
	pong, _ := ab.Seal(nil, msgs["pong_v6"], fixedReader(1))
	if len(pong) >= len(ping) {
		t.Fatalf("pong %d bytes ≥ ping %d bytes: amplification", len(pong), len(ping))
	}
}

func TestOpenRejects(t *testing.T) {
	t.Parallel()
	ab, ba := peerKeys(t)
	a, _ := testKeys(t)
	other, _ := key.DiscoPrivateFromBytes(bytes.Repeat([]byte{0x44}, key.Size))
	outsider, _ := NewPeerKey(other, a.Public())
	good, err := ab.Seal(nil, sampleMessages()["ping"], fixedReader(0x5a))
	if err != nil {
		t.Fatal(err)
	}
	flip := func(i int) []byte {
		p := bytes.Clone(good)
		p[i] ^= 0x01
		return p
	}
	fromOutsider, _ := outsider.Seal(nil, sampleMessages()["ping"], fixedReader(1))
	tests := []struct {
		name   string
		packet []byte
		want   error
	}{
		{"empty", nil, ErrNotDisco},
		{"truncated", good[:minPacketLen-1], ErrNotDisco},
		{"oversize", append(bytes.Clone(good), make([]byte, MaxPacketSize)...), ErrNotDisco},
		{"bad magic", flip(0), ErrNotDisco},
		{"sender changed", flip(magicSize), ErrWrongSender},
		{"nonce changed", flip(magicSize + key.Size), ErrAuth},
		{"ciphertext changed", flip(headerSize + 1), ErrAuth},
		{"tag changed", flip(len(good) - 1), ErrAuth},
		{"unknown sender key", fromOutsider, ErrWrongSender},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ba.Open(tt.packet); !errors.Is(err, tt.want) {
				t.Fatalf("Open error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestParsePlaintextRejectsInvalidBodies(t *testing.T) {
	t.Parallel()
	valid, err := MarshalPlaintext(sampleMessages()["call_me_maybe"])
	if err != nil {
		t.Fatal(err)
	}
	ping, _ := MarshalPlaintext(sampleMessages()["ping"])
	pong, _ := MarshalPlaintext(sampleMessages()["pong_v4"])
	mutate := func(src []byte, f func([]byte) []byte) []byte { return f(bytes.Clone(src)) }
	tests := []struct {
		name string
		b    []byte
		want error
	}{
		{"short", []byte{Version}, ErrMalformed},
		{"version 1", mutate(valid, func(b []byte) []byte { b[0] = 1; return b }), ErrUnsupported},
		{"unknown type", mutate(valid, func(b []byte) []byte { b[1] = 0x7f; return b }), ErrUnsupported},
		{"reserved type", mutate(valid, func(b []byte) []byte { b[1] = 0x10; return b }), ErrUnsupported},
		{"reserved flag", mutate(valid, func(b []byte) []byte { b[2+19] |= 0x80; return b }), ErrMalformed},
		{"bad nat mapping", mutate(valid, func(b []byte) []byte { b[2+16] = 9; return b }), ErrMalformed},
		{"count too large", mutate(valid, func(b []byte) []byte { b[2+20] = MaxEndpoints + 1; return b }), ErrMalformed},
		{"count mismatch", mutate(valid, func(b []byte) []byte { return b[:len(b)-1] }), ErrMalformed},
		{"bad endpoint kind", mutate(valid, func(b []byte) []byte { b[2+cmmFixedSize] = 0; return b }), ErrMalformed},
		{"endpoint port zero", mutate(valid, func(b []byte) []byte {
			b[2+cmmFixedSize+1+16], b[2+cmmFixedSize+1+17] = 0, 0
			return b
		}), ErrMalformed},
		{"ping zero txid", mutate(ping, func(b []byte) []byte { clear(b[2 : 2+TxIDSize]); return b }), ErrMalformed},
		{"ping nonzero padding", append(bytes.Clone(ping), 1), ErrMalformed},
		{"ping truncated", ping[:len(ping)-1], ErrMalformed},
		{"pong trailing byte", append(bytes.Clone(pong), 0), ErrMalformed},
		{"pong unspecified address", mutate(pong, func(b []byte) []byte {
			clear(b[2+TxIDSize : 2+TxIDSize+16])
			return b
		}), ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := ParsePlaintext(tt.b); !errors.Is(err, tt.want) {
				t.Fatalf("ParsePlaintext error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestMarshalRejectsInvalidMessages(t *testing.T) {
	t.Parallel()
	tooMany := make([]Endpoint, MaxEndpoints+1)
	for i := range tooMany {
		tooMany[i] = Endpoint{Kind: EndpointHost, Addr: netip.MustParseAddrPort("192.0.2.1:1")}
	}
	tests := map[string]Message{
		"nil":           nil,
		"ping zero":     Ping{},
		"pong no txid":  Pong{Observed: netip.MustParseAddrPort("192.0.2.1:5")},
		"pong bad addr": Pong{TxID: TxID{1}, Observed: netip.MustParseAddrPort("224.0.0.1:5")},
		"cmm too many":  CallMeMaybe{Endpoints: tooMany},
		"cmm bad flag":  CallMeMaybe{Flags: 0x80},
		"cmm multicast": CallMeMaybe{Endpoints: []Endpoint{{Kind: EndpointHost, Addr: netip.MustParseAddrPort("224.0.0.1:5")}}},
		"cmm bad kind":  CallMeMaybe{Endpoints: []Endpoint{{Kind: 9, Addr: netip.MustParseAddrPort("192.0.2.1:5")}}},
		"ping huge pad": Ping{TxID: TxID{1}, Node: key.NodePublic{1}, Padding: MaxPacketSize + 1},
	}
	for name, m := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := MarshalPlaintext(m); !errors.Is(err, ErrMalformed) {
				t.Fatalf("MarshalPlaintext error = %v, want ErrMalformed", err)
			}
		})
	}
	ab, _ := peerKeys(t)
	if _, err := ab.Seal(nil, Ping{TxID: TxID{1}, Node: key.NodePublic{1}, Padding: MaxPacketSize - 50}, fixedReader(1)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("oversize envelope sealed: %v", err)
	}
}

func TestReplayGuard(t *testing.T) {
	t.Parallel()
	now := time.UnixMilli(1760000000000)
	clock := func() time.Time { return now }
	sender := key.DiscoPublic{1}
	msg := func(seq uint64, sentAt time.Time) CallMeMaybe {
		return CallMeMaybe{Seq: seq, SentAt: sentAt.UnixMilli()}
	}

	g := &ReplayGuard{Now: clock}
	if err := g.Accept(sender, msg(5, now)); err != nil {
		t.Fatalf("first accept: %v", err)
	}
	if err := g.Accept(sender, msg(5, now)); !errors.Is(err, ErrReplay) {
		t.Fatalf("same seq: %v", err)
	}
	if err := g.Accept(sender, msg(4, now)); !errors.Is(err, ErrReplay) {
		t.Fatalf("older seq: %v", err)
	}
	if err := g.Accept(sender, msg(6, now)); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("burst: %v", err)
	}
	now = now.Add(MinCallMeMaybeInterval)
	if err := g.Accept(sender, msg(6, now)); err != nil {
		t.Fatalf("after interval: %v", err)
	}
	if err := g.Accept(sender, msg(9, now.Add(-MaxClockSkew-time.Millisecond))); !errors.Is(err, ErrStale) {
		t.Fatalf("old timestamp: %v", err)
	}
	if err := g.Accept(sender, msg(9, now.Add(MaxClockSkew+time.Millisecond))); !errors.Is(err, ErrStale) {
		t.Fatalf("future timestamp: %v", err)
	}
	g.Forget(sender)
	if g.Len() != 0 {
		t.Fatal("Forget kept state")
	}
	if err := g.Accept(sender, msg(1, now)); err != nil {
		t.Fatalf("after forget: %v", err)
	}
}

func TestReplayGuardConcurrentSequencesAcceptOnce(t *testing.T) {
	t.Parallel()
	g := &ReplayGuard{}
	sender := key.DiscoPublic{2}
	sentAt := time.Now().UnixMilli()
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for range 64 {
		wg.Go(func() {
			if g.Accept(sender, CallMeMaybe{Seq: 1, SentAt: sentAt}) == nil {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if accepted != 1 {
		t.Fatalf("seq 1 accepted %d times", accepted)
	}
}

// vectorFile is the JSON layout of testdata/vectors.json (disco-v2 §5).
type vectorFile struct {
	PrivateA   string          `json:"private_a"`
	PrivateB   string          `json:"private_b"`
	PublicA    string          `json:"public_a"`
	PublicB    string          `json:"public_b"`
	MessageKey string          `json:"message_key"`
	Nonce      string          `json:"nonce"`
	Valid      []vectorEntry   `json:"valid"`
	Invalid    []invalidVector `json:"invalid"`
}

type vectorEntry struct {
	Name      string `json:"name"`
	Plaintext string `json:"plaintext"`
	Envelope  string `json:"envelope"`
}

type invalidVector struct {
	Name     string `json:"name"`
	Envelope string `json:"envelope"`
}

func buildVectors(t *testing.T) vectorFile {
	t.Helper()
	a, b := testKeys(t)
	ab, _ := peerKeys(t)
	shared, err := a.Shared(b.Public())
	if err != nil {
		t.Fatal(err)
	}
	k, err := deriveKey(shared, a.Public(), b.Public())
	if err != nil {
		t.Fatal(err)
	}
	v := vectorFile{
		PrivateA: hex.EncodeToString(bytes.Repeat([]byte{0x11}, key.Size)),
		PrivateB: hex.EncodeToString(bytes.Repeat([]byte{0x22}, key.Size)),
		PublicA:  a.Public().String(), PublicB: b.Public().String(),
		MessageKey: hex.EncodeToString(k[:]),
		Nonce:      hex.EncodeToString(bytes.Repeat([]byte{0x5a}, nonceSize)),
	}
	for _, name := range []string{"ping", "ping_padded", "pong_v4", "pong_v6", "pong_relayed", "call_me_maybe", "call_me_maybe_empty"} {
		m := sampleMessages()[name]
		plaintext, err := MarshalPlaintext(m)
		if err != nil {
			t.Fatal(err)
		}
		envelope, err := ab.Seal(nil, m, fixedReader(0x5a))
		if err != nil {
			t.Fatal(err)
		}
		v.Valid = append(v.Valid, vectorEntry{Name: name, Plaintext: hex.EncodeToString(plaintext), Envelope: hex.EncodeToString(envelope)})
	}
	ping, _ := ab.Seal(nil, sampleMessages()["ping"], fixedReader(0x5a))
	tampered := bytes.Clone(ping)
	tampered[len(tampered)-1] ^= 1
	v.Invalid = []invalidVector{
		{Name: "tampered tag", Envelope: hex.EncodeToString(tampered)},
		{Name: "truncated", Envelope: hex.EncodeToString(ping[:minPacketLen-1])},
		{Name: "bad magic", Envelope: hex.EncodeToString(append([]byte{0}, ping[1:]...))},
	}
	return v
}

func TestVectors(t *testing.T) {
	t.Parallel()
	got := buildVectors(t)
	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if *update {
		if err := os.WriteFile(vectorsPath, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors (run with -update to create): %v", err)
	}
	if !bytes.Equal(want, encoded) {
		t.Fatal("implementation no longer reproduces testdata/vectors.json")
	}
	_, ba := peerKeys(t)
	for _, inv := range got.Invalid {
		packet, _ := hex.DecodeString(inv.Envelope)
		if _, err := ba.Open(packet); err == nil {
			t.Errorf("invalid vector %q accepted", inv.Name)
		}
	}
}

func FuzzParsePlaintext(f *testing.F) {
	for _, m := range sampleMessages() {
		b, _ := MarshalPlaintext(m)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParsePlaintext(b)
		if err != nil {
			return
		}
		again, err := MarshalPlaintext(m)
		if err != nil {
			t.Fatalf("parsed message does not re-marshal: %v", err)
		}
		if !bytes.Equal(again, b) {
			t.Fatalf("non-canonical encoding accepted:\n in %x\nout %x", b, again)
		}
	})
}

func FuzzOpen(f *testing.F) {
	ab, ba := peerKeysForFuzz(f)
	for _, m := range sampleMessages() {
		p, _ := ab.Seal(nil, m, fixedReader(3))
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, packet []byte) {
		_, _ = ba.Open(packet) // must never panic
	})
}

func peerKeysForFuzz(f *testing.F) (ab, ba *PeerKey) {
	a, _ := key.DiscoPrivateFromBytes(bytes.Repeat([]byte{0x11}, key.Size))
	b, _ := key.DiscoPrivateFromBytes(bytes.Repeat([]byte{0x22}, key.Size))
	var err error
	if ab, err = NewPeerKey(a, b.Public()); err != nil {
		f.Fatal(err)
	}
	if ba, err = NewPeerKey(b, a.Public()); err != nil {
		f.Fatal(err)
	}
	return ab, ba
}

func BenchmarkSealOpenPing(b *testing.B) {
	a, _ := key.DiscoPrivateFromBytes(bytes.Repeat([]byte{0x11}, key.Size))
	c, _ := key.DiscoPrivateFromBytes(bytes.Repeat([]byte{0x22}, key.Size))
	ac, _ := NewPeerKey(a, c.Public())
	ca, _ := NewPeerKey(c, a.Public())
	m := sampleMessages()["ping"]
	buf := make([]byte, 0, MaxPacketSize)
	b.ReportAllocs()
	for b.Loop() {
		p, err := ac.Seal(buf[:0], m, fixedReader(1))
		if err != nil {
			b.Fatal(err)
		}
		if _, err := ca.Open(p); err != nil {
			b.Fatal(err)
		}
	}
}

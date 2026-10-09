package mtrp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"math/rand/v2"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"meshtransit.net/shared/key"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors.json")

// vectorsPath is the committed test vector file this package must reproduce.
const vectorsPath = "testdata/vectors.json"

type fixedReader byte

func (r fixedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(r)
	}
	return len(p), nil
}

// ---------- frames ----------

func TestDataRoundTripDoesNotAllocate(t *testing.T) {
	payload := bytes.Repeat([]byte{0xab}, 1200)
	buf := make([]byte, 0, MaxUDPFrame)
	frame, err := AppendData(buf, 7, 9, payload)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseData(frame)
	if err != nil || d.ReceiverIndex != 7 || d.Route != 9 || !bytes.Equal(d.Payload, payload) {
		t.Fatalf("ParseData = %+v, %v", d, err)
	}
	allocs := testing.AllocsPerRun(100, func() {
		f, _ := AppendData(buf[:0], 7, 9, payload)
		_, _ = ParseData(f)
	})
	if allocs != 0 {
		t.Fatalf("DATA path allocates %.1f times per frame", allocs)
	}
}

func TestHandshakeFramesRoundTrip(t *testing.T) {
	t.Parallel()
	relay, _ := key.RelayPrivateFromBytes(bytes.Repeat([]byte{0x31}, key.Size))
	macs := NewRelayMACKeys(relay.Public())
	noise := bytes.Repeat([]byte{0xcc}, minNoiseInit+40)

	init, err := AppendInitWithoutMACs(nil, 0x01020304, noise)
	if err != nil {
		t.Fatal(err)
	}
	mac1 := macs.MAC1(init)
	init = AppendMACs(init, mac1, [MACSize]byte{})
	parsed, err := ParseInit(init)
	if err != nil || parsed.SenderIndex != 0x01020304 || !bytes.Equal(parsed.Noise, noise) || parsed.MAC1 != mac1 {
		t.Fatalf("ParseInit = %+v, %v", parsed, err)
	}
	before1, before2, err := MACInput(init)
	if err != nil || !macs.CheckMAC1(before1, parsed.MAC1) || len(before2) != len(before1)+MACSize {
		t.Fatal("mac1 does not verify over the parsed frame")
	}

	resp, err := AppendResponseWithoutMACs(nil, 5, 0x01020304, noise[:minNoiseResponse])
	if err != nil {
		t.Fatal(err)
	}
	resp = AppendMACs(resp, macs.MAC1(resp), [MACSize]byte{})
	if len(resp) >= len(init) {
		t.Fatalf("RESPONSE (%d) not smaller than INIT (%d): amplification", len(resp), len(init))
	}
	r, err := ParseResponse(resp)
	if err != nil || r.SenderIndex != 5 || r.ReceiverIndex != 0x01020304 {
		t.Fatalf("ParseResponse = %+v, %v", r, err)
	}

	cookie, err := AppendCookie(nil, Cookie{ReceiverIndex: 0x01020304})
	if err != nil {
		t.Fatal(err)
	}
	if len(cookie) >= len(init) {
		t.Fatal("COOKIE not smaller than INIT")
	}
	if c, err := ParseCookie(cookie); err != nil || c.ReceiverIndex != 0x01020304 {
		t.Fatalf("ParseCookie = %+v, %v", c, err)
	}

	ctl, err := AppendControlHeader(nil, 11, 99)
	if err != nil {
		t.Fatal(err)
	}
	ctl = append(ctl, bytes.Repeat([]byte{1}, controlTagSize+1)...)
	if c, err := ParseControl(ctl); err != nil || c.ReceiverIndex != 11 || c.Counter != 99 {
		t.Fatalf("ParseControl = %+v, %v", c, err)
	}
}

func TestFramesReject(t *testing.T) {
	t.Parallel()
	data, _ := AppendData(nil, 1, 2, []byte{1})
	mutate := func(f func([]byte) []byte) []byte { return f(bytes.Clone(data)) }
	tests := []struct {
		name  string
		frame []byte
		parse func([]byte) error
		want  error
	}{
		{"empty", nil, dataErr, ErrMalformed},
		{"version 2", mutate(func(b []byte) []byte { b[0] = 2; return b }), dataErr, ErrUnsupported},
		{"reserved set", mutate(func(b []byte) []byte { b[3] = 1; return b }), dataErr, ErrUnsupported},
		{"unknown type", mutate(func(b []byte) []byte { b[1] = 9; return b }), dataErr, ErrUnsupported},
		{"zero receiver", mutate(func(b []byte) []byte { clear(b[4:8]); return b }), dataErr, ErrMalformed},
		{"zero route", mutate(func(b []byte) []byte { clear(b[8:12]); return b }), dataErr, ErrMalformed},
		{"no payload", data[:12], dataErr, ErrMalformed},
		{"oversize", append(bytes.Clone(data), make([]byte, MaxStreamFrame)...), dataErr, ErrMalformed},
		{"data as init", data, func(b []byte) error { _, err := ParseInit(b); return err }, ErrMalformed},
		{
			"short init", append([]byte{1, 1, 0, 0, 0, 0, 0, 1}, make([]byte, 20)...),
			func(b []byte) error { _, err := ParseInit(b); return err }, ErrMalformed,
		},
		{"short control", []byte{1, 4, 0, 0, 0, 0, 0, 1}, func(b []byte) error { _, err := ParseControl(b); return err }, ErrMalformed},
		{"cookie wrong size", []byte{1, 3, 0, 0, 0, 0, 0, 1}, func(b []byte) error { _, err := ParseCookie(b); return err }, ErrMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := tt.parse(tt.frame); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
	if _, err := AppendData(nil, 1, 1, make([]byte, MaxDataPayload+1)); !errors.Is(err, ErrMalformed) {
		t.Fatal("oversized DATA payload encoded")
	}
}

func dataErr(b []byte) error { _, err := ParseData(b); return err }

// ---------- control messages ----------

func sampleControls(t *testing.T) []ControlMessage {
	t.Helper()
	peer := key.NodePublic{1, 2, 3}
	return []ControlMessage{
		{Type: ControlKeepalive},
		{Type: ControlRouteOpen, Request: 1, Peer: peer},
		{Type: ControlRouteOK, Request: 1, Route: 77},
		{Type: ControlRouteError, Request: 1, RouteError: RouteErrorPeerAbsent},
		{Type: ControlRouteIncoming, Route: 78, Peer: peer},
		{Type: ControlRouteClose, Route: 78, RouteClose: RouteCloseRevoked},
		{Type: ControlTicketUpdate, Ticket: []byte("ticket-bytes")},
		{Type: ControlTicketAck, NotAfterMS: 1760000900000},
		{Type: ControlSessionClose, SessionClose: SessionCloseDraining, RetryAfterMS: 2500},
	}
}

func TestControlMessagesRoundTrip(t *testing.T) {
	t.Parallel()
	for _, m := range sampleControls(t) {
		encoded, err := AppendControlMessage(nil, m)
		if err != nil {
			t.Fatalf("%v: %v", m.Type, err)
		}
		got, err := ParseControlMessage(encoded)
		if err != nil || !reflect.DeepEqual(got, m) {
			t.Fatalf("%v: got %+v, %v", m.Type, got, err)
		}
		if _, err := ParseControlMessage(append(encoded, 0)); err == nil {
			t.Fatalf("%v: trailing byte accepted", m.Type)
		}
	}
	for _, bad := range []ControlMessage{
		{Type: 0x7f},
		{Type: ControlRouteOpen, Request: 1},
		{Type: ControlRouteError, Request: 1, RouteError: 9},
		{Type: ControlTicketUpdate, Ticket: make([]byte, MaxTicketSize+1)},
		{Type: ControlSessionClose},
	} {
		if _, err := AppendControlMessage(nil, bad); err == nil {
			t.Fatalf("invalid control %+v encoded", bad)
		}
	}
}

// ---------- tickets ----------

func signingKey(t testing.TB) key.SigningPrivate {
	t.Helper()
	s, err := key.SigningPrivateFromSeed(bytes.Repeat([]byte{0x41}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func sampleTicket() Ticket {
	return Ticket{
		ID:         [16]byte{0x01, 0x99, 0x5d},
		IssuedAtMS: 1760000000000,
		NotAfterMS: 1760000000000 + (10 * time.Minute).Milliseconds(),
		Node:       key.NodePublic{0x10, 0x20},
		Disco:      key.DiscoPublic{0x30, 0x40},
		Deployment: [16]byte{0x01, 0x99, 0x5d, 0x00, 0x00, 0x00, 0x70, 0x00, 0x80},
		MaxBPS:     1 << 20,
		MaxRoutes:  256,
		// Deliberately unsorted: Sign canonicalises.
		Zones: []Zone{{Kind: ZoneTrustContract, ID: [16]byte{9}}, {Kind: ZoneNetwork, ID: [16]byte{5}}},
	}
}

func verifierAt(t testing.TB, nowMS int64) Verifier {
	return Verifier{Keys: NewStaticKeys(signingKey(t).Public()), Now: func() time.Time { return time.UnixMilli(nowMS) }}
}

func TestTicketSignVerify(t *testing.T) {
	t.Parallel()
	signed, err := sampleTicket().Sign(signingKey(t))
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifierAt(t, 1760000060000).Verify(signed)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Zones[0].Kind != ZoneNetwork || got.KeyID != signingKey(t).Public().ID() || got.Node != sampleTicket().Node {
		t.Fatalf("decoded ticket = %+v", got)
	}
}

type revokeAll struct{}

func (revokeAll) Revoked(Ticket) bool { return true }

func TestTicketRejects(t *testing.T) {
	t.Parallel()
	signed, _ := sampleTicket().Sign(signingKey(t))
	other, _ := key.SigningPrivateFromSeed(bytes.Repeat([]byte{0x42}, 32))
	byOther, _ := sampleTicket().Sign(other)
	flip := func(i int) []byte { b := bytes.Clone(signed); b[i] ^= 1; return b }
	issued, notAfter := sampleTicket().IssuedAtMS, sampleTicket().NotAfterMS
	tests := []struct {
		name   string
		ticket []byte
		v      Verifier
		want   error
	}{
		{"unknown key", byOther, verifierAt(t, issued), ErrTicketUnknownKey},
		{"no key set", signed, Verifier{}, ErrTicketUnknownKey},
		{"tampered node", flip(4 + 8 + 16 + 16), verifierAt(t, issued), ErrTicketSignature},
		{"tampered signature", flip(len(signed) - 1), verifierAt(t, issued), ErrTicketSignature},
		{"bad magic", flip(0), verifierAt(t, issued), ErrTicketMalformed},
		{"truncated", signed[:len(signed)-1], verifierAt(t, issued), ErrTicketMalformed},
		{"trailing", append(bytes.Clone(signed), 0), verifierAt(t, issued), ErrTicketMalformed},
		{"expired", signed, verifierAt(t, notAfter), ErrTicketTime},
		{"from the future", signed, verifierAt(t, issued-MaxIssueSkew.Milliseconds()-1), ErrTicketTime},
		{"revoked", signed, Verifier{
			Keys: NewStaticKeys(signingKey(t).Public()), Revocations: revokeAll{},
			Now: func() time.Time { return time.UnixMilli(issued) },
		}, ErrTicketRevoked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := tt.v.Verify(tt.ticket); !errors.Is(err, tt.want) {
				t.Fatalf("Verify error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestTicketSignRejectsInvalidFields(t *testing.T) {
	t.Parallel()
	mod := func(f func(*Ticket)) Ticket { tk := sampleTicket(); f(&tk); return tk }
	tooMany := make([]Zone, MaxZones+1)
	for i := range tooMany {
		tooMany[i] = Zone{Kind: ZoneNetwork, ID: [16]byte{byte(i + 1)}}
	}
	for name, tk := range map[string]Ticket{
		"lifetime too long": mod(func(t *Ticket) { t.NotAfterMS = t.IssuedAtMS + MaxTicketLifetime.Milliseconds() + 1 }),
		"not after first":   mod(func(t *Ticket) { t.NotAfterMS = t.IssuedAtMS }),
		"no zones":          mod(func(t *Ticket) { t.Zones = nil }),
		"too many zones":    mod(func(t *Ticket) { t.Zones = tooMany }),
		"duplicate zone":    mod(func(t *Ticket) { t.Zones = []Zone{{ZoneNetwork, [16]byte{1}}, {ZoneNetwork, [16]byte{1}}} }),
		"unknown zone kind": mod(func(t *Ticket) { t.Zones = []Zone{{Kind: 3, ID: [16]byte{1}}} }),
		"zero disco":        mod(func(t *Ticket) { t.Disco = key.DiscoPublic{} }),
	} {
		if _, err := tk.Sign(signingKey(t)); !errors.Is(err, ErrTicketMalformed) {
			t.Errorf("%s: Sign error = %v, want ErrTicketMalformed", name, err)
		}
	}
}

func TestSharesZone(t *testing.T) {
	t.Parallel()
	z := func(kind ZoneKind, id byte) Zone { return Zone{Kind: kind, ID: [16]byte{id}} }
	a := Ticket{Zones: []Zone{z(ZoneNetwork, 1), z(ZoneNetwork, 3), z(ZoneTrustContract, 7)}}
	tests := []struct {
		name string
		b    []Zone
		want bool
	}{
		{"same network", []Zone{z(ZoneNetwork, 3)}, true},
		{"shared contract", []Zone{z(ZoneNetwork, 2), z(ZoneTrustContract, 7)}, true},
		{"same id different kind", []Zone{z(ZoneTrustContract, 1)}, false},
		{"disjoint", []Zone{z(ZoneNetwork, 2), z(ZoneNetwork, 4)}, false},
	}
	for _, tt := range tests {
		if got := SharesZone(a, Ticket{Zones: tt.b}); got != tt.want {
			t.Errorf("%s: SharesZone = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// ---------- cookies ----------

func TestCookieFlow(t *testing.T) {
	t.Parallel()
	relay, _ := key.RelayPrivateFromBytes(bytes.Repeat([]byte{0x31}, key.Size))
	macs := NewRelayMACKeys(relay.Public())
	now := time.UnixMilli(1760000000000)
	jar, err := NewCookieJar(fixedReader(0x77), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	client := netip.MustParseAddrPort("198.51.100.4:50123")
	cookie, _ := jar.Cookie(client)
	other, _ := jar.Cookie(netip.MustParseAddrPort("198.51.100.4:50124"))
	if cookie == other {
		t.Fatal("cookie not bound to the source port")
	}

	init, _ := AppendInitWithoutMACs(nil, 1, bytes.Repeat([]byte{1}, minNoiseInit))
	mac1 := macs.MAC1(init)
	nonce, sealed, err := macs.SealCookie(cookie, mac1, fixedReader(0x55))
	if err != nil {
		t.Fatal(err)
	}
	opened, err := macs.OpenCookie(Cookie{ReceiverIndex: 1, Nonce: nonce, EncryptedCookie: sealed}, mac1)
	if err != nil || opened != cookie {
		t.Fatalf("OpenCookie = %x, %v", opened, err)
	}
	if _, err := macs.OpenCookie(Cookie{ReceiverIndex: 1, Nonce: nonce, EncryptedCookie: sealed}, [MACSize]byte{1}); !errors.Is(err, ErrCookie) {
		t.Fatal("cookie opened with a different mac1")
	}
	withMAC1 := append(bytes.Clone(init), mac1[:]...)
	mac2 := MAC2(opened, withMAC1)
	if !CheckMAC2(cookie, withMAC1, mac2) || CheckMAC2(other, withMAC1, mac2) {
		t.Fatal("mac2 check wrong")
	}

	now = now.Add(CookieSecretLifetime)
	rotated, _ := jar.Cookie(client)
	_ = rotated // with a fixed reader the secret repeats; rotation timing is what we check
	if jar.created != now {
		t.Fatal("cookie secret not rotated after its lifetime")
	}
	if _, err := NewCookieJar(nil, nil); err == nil {
		t.Fatal("cookie jar without randomness accepted")
	}
}

// ---------- replay window ----------

// modelWindow is the obvious reference: a set of seen counters plus the rule
// that counters older than the window are rejected.
type modelWindow struct {
	seen    map[uint64]bool
	highest uint64
	started bool
}

func (m *modelWindow) accept(c uint64) bool {
	if m.seen == nil {
		m.seen = map[uint64]bool{}
	}
	if m.started && c <= m.highest && m.highest-c >= ReplayWindowSize {
		return false
	}
	if m.seen[c] {
		return false
	}
	m.seen[c] = true
	if !m.started || c > m.highest {
		m.highest, m.started = c, true
	}
	return true
}

func TestReplayWindowMatchesModel(t *testing.T) {
	t.Parallel()
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // deterministic test sequence, not a secret
	for trial := range 2000 {
		var w ReplayWindow
		var m modelWindow
		base := rng.Uint64N(1 << 40)
		for step := range 300 {
			// Mix forward jumps (small and huge), in-window replays and stale counters.
			var c uint64
			switch rng.IntN(5) {
			case 0:
				c = base + rng.Uint64N(64)
			case 1:
				c = base + rng.Uint64N(5000)
			case 2:
				c = base + rng.Uint64N(3*ReplayWindowSize)
			case 3:
				if m.highest > ReplayWindowSize {
					c = m.highest - ReplayWindowSize + rng.Uint64N(8) - 4 // around the window edge
				} else {
					c = base
				}
			default:
				c = m.highest - rng.Uint64N(ReplayWindowSize+64)
			}
			if got, want := w.Accept(c), m.accept(c); got != want {
				t.Fatalf("trial %d step %d counter %d (highest %d): window=%v model=%v", trial, step, c, m.highest, got, want)
			}
			if rng.IntN(20) == 0 {
				base = m.highest + rng.Uint64N(100)
			}
		}
	}
}

func TestReplayWindowEdges(t *testing.T) {
	t.Parallel()
	var w ReplayWindow
	if !w.Accept(5000) || w.Accept(5000) {
		t.Fatal("duplicate accepted")
	}
	if !w.Accept(5000 - ReplayWindowSize + 1) {
		t.Fatal("oldest in-window counter rejected")
	}
	if w.Accept(5000 - ReplayWindowSize + 1) {
		t.Fatal("replay at the window edge accepted")
	}
	if w.Accept(5000 - ReplayWindowSize) {
		t.Fatal("counter just outside the window accepted")
	}
	if !w.Accept(1<<62) || w.Accept(5001) {
		t.Fatal("huge jump did not invalidate old counters")
	}
}

// ---------- vectors ----------

type vectorFile struct {
	SigningSeed string            `json:"signing_seed"`
	SigningKey  string            `json:"signing_public"`
	KeyID       string            `json:"key_id"`
	Ticket      string            `json:"ticket"`
	RelayKey    string            `json:"relay_public"`
	MAC1Input   string            `json:"mac1_input"`
	MAC1        string            `json:"mac1"`
	Frames      map[string]string `json:"frames"`
	Invalid     map[string]string `json:"invalid"`
}

func buildVectors(t *testing.T) vectorFile {
	t.Helper()
	signer := signingKey(t)
	ticket, err := sampleTicket().Sign(signer)
	if err != nil {
		t.Fatal(err)
	}
	relay, _ := key.RelayPrivateFromBytes(bytes.Repeat([]byte{0x31}, key.Size))
	macs := NewRelayMACKeys(relay.Public())
	init, _ := AppendInitWithoutMACs(nil, 0x01020304, bytes.Repeat([]byte{0xcc}, minNoiseInit))
	mac1 := macs.MAC1(init)
	data, _ := AppendData(nil, 7, 9, []byte("payload"))
	ctlHeader, _ := AppendControlHeader(nil, 11, 99)
	frames := map[string]string{
		"init_without_macs": hex.EncodeToString(init),
		"data":              hex.EncodeToString(data),
		"control_header":    hex.EncodeToString(ctlHeader),
	}
	for _, m := range sampleControls(t) {
		b, _ := AppendControlMessage(nil, m)
		frames["control_"+hex.EncodeToString([]byte{byte(m.Type)})] = hex.EncodeToString(b)
	}
	tampered := bytes.Clone(ticket)
	tampered[len(tampered)-1] ^= 1
	return vectorFile{
		SigningSeed: hex.EncodeToString(bytes.Repeat([]byte{0x41}, 32)),
		SigningKey:  signer.Public().String(),
		KeyID:       signer.Public().ID().String(),
		Ticket:      hex.EncodeToString(ticket),
		RelayKey:    relay.Public().String(),
		MAC1Input:   hex.EncodeToString(init),
		MAC1:        hex.EncodeToString(mac1[:]),
		Frames:      frames,
		Invalid: map[string]string{
			"ticket_tampered_signature": hex.EncodeToString(tampered),
			"ticket_truncated":          hex.EncodeToString(ticket[:len(ticket)-1]),
			"data_zero_route":           hex.EncodeToString(append(data[:8:8], 0, 0, 0, 0, 'x')),
		},
	}
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
	v := verifierAt(t, sampleTicket().IssuedAtMS)
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range got.Invalid {
			if !yield(k) {
				return
			}
		}
	}) {
		b, _ := hex.DecodeString(got.Invalid[name])
		_, ticketErr := v.Verify(b)
		_, dataErr := ParseData(b)
		if ticketErr == nil && dataErr == nil {
			t.Errorf("invalid vector %q accepted", name)
		}
	}
}

// ---------- fuzzing ----------

func FuzzParseFrames(f *testing.F) {
	data, _ := AppendData(nil, 1, 2, []byte("x"))
	f.Add(data)
	init, _ := AppendInitWithoutMACs(nil, 1, make([]byte, minNoiseInit))
	f.Add(AppendMACs(init, [MACSize]byte{}, [MACSize]byte{}))
	f.Fuzz(func(t *testing.T, b []byte) {
		if d, err := ParseData(b); err == nil {
			again, err := AppendData(nil, d.ReceiverIndex, d.Route, d.Payload)
			if err != nil || !bytes.Equal(again, b) {
				t.Fatalf("DATA not canonical: %x", b)
			}
		}
		_, _ = ParseInit(b)
		_, _ = ParseResponse(b)
		_, _ = ParseCookie(b)
		_, _ = ParseControl(b)
	})
}

func FuzzParseControlMessage(f *testing.F) {
	for _, m := range sampleControls(&testing.T{}) {
		b, _ := AppendControlMessage(nil, m)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := ParseControlMessage(b)
		if err != nil {
			return
		}
		again, err := AppendControlMessage(nil, m)
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("control message not canonical: %x", b)
		}
	})
}

func FuzzVerifyTicket(f *testing.F) {
	signed, _ := sampleTicket().Sign(signingKey(f))
	f.Add(signed)
	v := verifierAt(f, sampleTicket().IssuedAtMS)
	f.Fuzz(func(t *testing.T, b []byte) {
		if _, err := v.Verify(b); err == nil && !bytes.Equal(b, signed) {
			t.Fatalf("forged ticket accepted: %x", b)
		}
	})
}

func BenchmarkVerifyTicket(b *testing.B) {
	signed, _ := sampleTicket().Sign(signingKey(b))
	v := verifierAt(b, sampleTicket().IssuedAtMS)
	b.ReportAllocs()
	for b.Loop() {
		if _, err := v.Verify(signed); err != nil {
			b.Fatal(err)
		}
	}
}

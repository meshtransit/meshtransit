package mtrp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"slices"
	"testing"
)

// testRand makes a test's shuffles and samples reproducible; each caller
// gets its own, as the tests run in parallel.
func testRand(seed uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed, 9)) //nolint:gosec // test data, not secrets
}

// contractZones returns a Network zone and n Trust Contract zones, unsorted.
func contractZones(n int) []Zone {
	zones := []Zone{{Kind: ZoneNetwork, ID: [16]byte{5}}}
	for i := range n {
		var id [16]byte
		binary.BigEndian.PutUint32(id[:], uint32(i+1))
		id[15] = 0x77
		zones = append(zones, Zone{Kind: ZoneTrustContract, ID: id})
	}
	seed := uint64(len(zones))
	testRand(seed).Shuffle(len(zones), func(i, j int) { zones[i], zones[j] = zones[j], zones[i] })
	return zones
}

func signedV2(t *testing.T, contracts int) (Ticket, []byte, []Zone) {
	t.Helper()
	tk := sampleTicket()
	tk.Zones = contractZones(contracts)
	raw, encoded, err := tk.SignZones(signingKey(t))
	if err != nil {
		t.Fatal(err)
	}
	zones, err := ParseZones(encoded)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifierAt(t, tk.IssuedAtMS).Verify(raw)
	if err != nil {
		t.Fatalf("Verify MTT2: %v", err)
	}
	return got, raw, zones
}

// TestTicketV2CommitsToTenThousandZones: an MTT2 ticket for 10,000
// contracts fits a handshake, carries the Network zone and the first
// contracts inline, and grants every zone only once the list matching its
// digest is added.
func TestTicketV2CommitsToTenThousandZones(t *testing.T) {
	t.Parallel()
	got, raw, zones := signedV2(t, 10_000)
	if len(raw) > MaxTicketSize || string(raw[:4]) != "MTT2" {
		t.Fatalf("MTT2 ticket of %d bytes, magic %q", len(raw), raw[:4])
	}
	if !got.IsV2() || got.ZoneTotal != 10_001 || len(got.Zones) != MaxZones || got.ZonesComplete() ||
		got.Zones[0].Kind != ZoneNetwork || !slices.Equal(got.Zones, zones[:MaxZones]) {
		t.Fatalf("decoded MTT2: total %d, %d inline, complete %v", got.ZoneTotal, len(got.Zones), got.ZonesComplete())
	}
	complete, err := got.WithZones(zones)
	if err != nil || !complete.ZonesComplete() || len(complete.Zones) != 10_001 {
		t.Fatalf("WithZones: %v", err)
	}
	altered := slices.Clone(zones)
	altered[5000].ID[0] ^= 1
	slices.SortFunc(altered, compareZones)
	for name, list := range map[string][]Zone{
		"altered zone": altered,
		"one missing":  zones[:len(zones)-1],
		"unsorted":     append([]Zone{zones[1], zones[0]}, zones[2:]...),
	} {
		if _, err := got.WithZones(list); !errors.Is(err, ErrTicketMalformed) {
			t.Errorf("%s: WithZones error = %v", name, err)
		}
	}
	// The digest binds the ticket ID: the same list under another ticket fails.
	other := got
	other.ID[0] ^= 1
	if _, err := other.WithZones(zones); err == nil {
		t.Error("zone list accepted under another ticket ID")
	}
	// A small MTT2 ticket is complete inline.
	small, _, _ := signedV2(t, 3)
	if !small.ZonesComplete() || small.ZoneTotal != 4 {
		t.Fatalf("small MTT2: %d of %d", len(small.Zones), small.ZoneTotal)
	}
	// Sign keeps producing MTT1 even from a ticket that was MTT2.
	v1, err := small.Sign(signingKey(t))
	if err != nil || string(v1[:4]) != "MTT1" {
		t.Fatalf("Sign after MTT2: %q, %v", v1[:4], err)
	}
}

func TestTicketV2Rejects(t *testing.T) {
	t.Parallel()
	_, raw, _ := signedV2(t, 100)
	issued := sampleTicket().IssuedAtMS
	flip := func(i int) []byte { b := bytes.Clone(raw); b[i] ^= 1; return b }
	totalAt := ticketFixedSize - 1
	for name, ticket := range map[string][]byte{
		"tampered digest":  flip(totalAt + 2),
		"tampered total":   flip(totalAt + 1),
		"truncated":        raw[:len(raw)-1],
		"inline too short": append(append(bytes.Clone(raw[:ticketV2Size-1]), MaxZones-1), raw[ticketV2Size:len(raw)-zoneSize]...),
	} {
		if _, err := verifierAt(t, issued).Verify(ticket); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	tk := sampleTicket()
	tk.Zones = contractZones(MaxTicketZones)
	if _, _, err := tk.SignZones(signingKey(t)); !errors.Is(err, ErrTicketMalformed) {
		t.Fatalf("SignZones over MaxTicketZones: %v", err)
	}
}

// TestZoneAssemblyFromFrames: the zones beyond the inline ones arrive in
// ZONES frames in any order, with duplicates; the assembly completes only
// with every zone and the right digest, and discards a corrupt pass.
func TestZoneAssemblyFromFrames(t *testing.T) {
	t.Parallel()
	got, _, zones := signedV2(t, 10_000)
	complete, _ := got.WithZones(zones)
	frames := ZoneFrames(complete)
	if want := (10_001 - MaxZones + MaxControlZones - 1) / MaxControlZones; len(frames) != want {
		t.Fatalf("%d ZONES frames, want %d", len(frames), want)
	}
	for _, frame := range frames {
		encoded, err := AppendControlMessage(nil, frame)
		if err != nil || len(encoded) > MaxControlPlaintext {
			t.Fatalf("encode ZONES: %v (%d bytes)", err, len(encoded))
		}
		parsed, err := ParseControlMessage(encoded)
		if err != nil || parsed.TicketID != frame.TicketID || parsed.ZoneOffset != frame.ZoneOffset ||
			!slices.Equal(parsed.Zones, frame.Zones) {
			t.Fatalf("ZONES round trip: %v", err)
		}
	}
	assembly, ok := NewZoneAssembly(got)
	if !ok {
		t.Fatal("no assembly for an incomplete MTT2 ticket")
	}
	shuffled := slices.Clone(frames)
	testRand(1).Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	for _, frame := range shuffled[:len(shuffled)-1] {
		first := assembly.Add(frame)
		if again := assembly.Add(frame); !first || !again { // a repeat is harmless
			t.Fatal("frame refused")
		}
	}
	if _, done := assembly.Complete(); done || assembly.Missing() == 0 {
		t.Fatal("complete before the last frame")
	}
	// Frames for another ticket, overwriting inline zones or past the end.
	foreign := frames[0]
	foreign.TicketID[0] ^= 1
	inline := frames[0]
	inline.ZoneOffset = 0
	past := frames[0]
	past.ZoneOffset = uint16(complete.ZoneTotal - len(past.Zones) + 1) //nolint:gosec // test sizes
	for name, frame := range map[string]ControlMessage{"foreign": foreign, "inline": inline, "past the end": past} {
		if assembly.Add(frame) {
			t.Errorf("%s frame accepted", name)
		}
	}
	// A corrupt last frame: the pass is discarded, and a clean one completes.
	corrupt := shuffled[len(shuffled)-1]
	corrupt.Zones = slices.Clone(corrupt.Zones)
	corrupt.Zones[0].ID[15] ^= 0x80
	assembly.Add(corrupt)
	if _, done := assembly.Complete(); done || assembly.Missing() != complete.ZoneTotal-MaxZones {
		t.Fatalf("corrupt pass: missing %d", assembly.Missing())
	}
	for _, frame := range frames {
		assembly.Add(frame)
	}
	final, done := assembly.Complete()
	if !done || !slices.Equal(final.Zones, zones) {
		t.Fatal("clean pass did not complete")
	}
	if _, ok := NewZoneAssembly(final); ok {
		t.Fatal("assembly for a complete ticket")
	}
}

func TestControlZonesRejects(t *testing.T) {
	t.Parallel()
	zones := slices.SortedFunc(slices.Values(contractZones(MaxControlZones)), compareZones)
	base := ControlMessage{Type: ControlZones, TicketID: [16]byte{1}, ZoneOffset: 32, Zones: zones[:MaxControlZones]}
	encoded, err := AppendControlMessage(nil, base)
	if err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]ControlMessage{
		"too many":  {Type: ControlZones, TicketID: [16]byte{1}, Zones: zones},
		"none":      {Type: ControlZones, TicketID: [16]byte{1}},
		"no ticket": {Type: ControlZones, Zones: zones[:1]},
		"unsorted":  {Type: ControlZones, TicketID: [16]byte{1}, Zones: []Zone{zones[1], zones[0]}},
		"past max":  {Type: ControlZones, TicketID: [16]byte{1}, ZoneOffset: MaxTicketZones, Zones: zones[:1]},
	} {
		if _, err := AppendControlMessage(nil, m); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	for name, b := range map[string][]byte{
		"truncated": encoded[:len(encoded)-1],
		"trailing":  append(bytes.Clone(encoded), 0),
		"count 0":   append(append(bytes.Clone(encoded[:19]), 0), encoded[20:]...),
	} {
		if _, err := ParseControlMessage(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

// TestSharedLiveZoneSearchesMatchMerge: the binary-search path for a small
// ticket against a large one finds the same zone as the merge walk.
func TestSharedLiveZoneSearchesMatchMerge(t *testing.T) {
	t.Parallel()
	large := Ticket{Zones: slices.SortedFunc(slices.Values(contractZones(5000)), compareZones)}
	random := testRand(2)
	for range 200 {
		var small Ticket
		for _, i := range random.Perm(len(large.Zones))[:random.IntN(4)] {
			small.Zones = append(small.Zones, large.Zones[i])
		}
		small.Zones = append(small.Zones, Zone{Kind: ZoneTrustContract, ID: [16]byte{0xff, uint8(random.Uint32() & 0xff)}})
		slices.SortFunc(small.Zones, compareZones)
		small.Zones = slices.Compact(small.Zones)
		got, found := SharedLiveZone(small, large, nil)
		var want Zone
		wantFound := false
		for _, z := range small.Zones {
			if _, ok := slices.BinarySearchFunc(large.Zones, z, compareZones); ok {
				want, wantFound = z, true
				break
			}
		}
		if found != wantFound || got != want || SharesLiveZone(large, small, nil) != wantFound {
			t.Fatalf("SharedLiveZone = %v %v, want %v %v", got, found, want, wantFound)
		}
		if wantFound && !HasLiveZone(large, want, nil) {
			t.Fatal("HasLiveZone missed a carried zone")
		}
	}
}

type withdrawn map[Zone]bool

func (withdrawn) Revoked(Ticket) bool       { return false }
func (w withdrawn) ZoneRevoked(z Zone) bool { return w[z] }

// TestIsRevokedJudgesInlineZonesUntilComplete: an MTT2 ticket still
// missing zones is revoked when every inline zone, its Network zone among
// them, is withdrawn (a Private Interchange relay not serving its Network);
// withdrawn inline contracts alone do not revoke it.
func TestIsRevokedJudgesInlineZonesUntilComplete(t *testing.T) {
	t.Parallel()
	got, _, zones := signedV2(t, 100)
	contractsOnly := withdrawn{}
	for _, z := range got.Zones[1:] {
		contractsOnly[z] = true
	}
	if IsRevoked(got, contractsOnly) {
		t.Fatal("pending MTT2 ticket revoked by its inline contracts")
	}
	all := withdrawn{}
	for _, z := range got.Zones {
		all[z] = true
	}
	if !IsRevoked(got, all) {
		t.Fatal("pending MTT2 ticket for an unserved Network admitted")
	}
	complete, _ := got.WithZones(zones)
	if IsRevoked(complete, all) {
		t.Fatal("complete ticket with live zones revoked")
	}
	if HasLiveZone(complete, got.Zones[0], all) {
		t.Fatal("withdrawn zone reported live")
	}
	for _, z := range zones {
		all[z] = true
	}
	if !IsRevoked(complete, all) {
		t.Fatal("complete ticket with every zone withdrawn not revoked")
	}
}

// TestTicketV2Bounds: small MTT2 tickets carry every zone inline, the
// largest fits MaxTicketSize, and a total past MaxTicketZones or an inline
// count other than min(total, 32) is refused on parse.
func TestTicketV2Bounds(t *testing.T) {
	t.Parallel()
	for _, contracts := range []int{0, MaxZones - 1, MaxZones, MaxTicketZones - 1} {
		tk := sampleTicket()
		tk.Zones = contractZones(contracts)
		raw, encoded, err := tk.SignZones(signingKey(t))
		if err != nil || len(raw) > MaxTicketSize {
			t.Fatalf("%d contracts: %d bytes, %v", contracts, len(raw), err)
		}
		got, err := verifierAt(t, tk.IssuedAtMS).Verify(raw)
		if err != nil || len(got.Zones) != min(contracts+1, MaxZones) || got.ZonesComplete() != (contracts+1 <= MaxZones) {
			t.Fatalf("%d contracts: %d inline, %v", contracts, len(got.Zones), err)
		}
		if _, err := CompleteTicket(raw, encoded); err != nil {
			t.Fatalf("%d contracts: CompleteTicket %v", contracts, err)
		}
	}
	tk := sampleTicket()
	tk.Zones = contractZones(10)
	raw, _, _ := tk.SignZones(signingKey(t))
	totalAt := ticketFixedSize - 1
	for name, mutate := range map[string]func([]byte){
		"total past the maximum": func(b []byte) { binary.BigEndian.PutUint16(b[totalAt:], MaxTicketZones+1) },
		"total above inline":     func(b []byte) { binary.BigEndian.PutUint16(b[totalAt:], 12) },
		"zero total":             func(b []byte) { binary.BigEndian.PutUint16(b[totalAt:], 0) },
	} {
		b := bytes.Clone(raw)
		mutate(b)
		if _, err := ParseTicketUnverified(b); !errors.Is(err, ErrTicketMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

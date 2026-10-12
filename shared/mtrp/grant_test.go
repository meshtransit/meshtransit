package mtrp

import (
	"bytes"
	"errors"
	"slices"
	"testing"
	"time"

	"meshtransit.net/shared/key"
)

func sampleGrant(t *testing.T) InterchangeGrant {
	t.Helper()
	signer := signingKey(t)
	payload, err := sampleMap().Payload(docNow)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := SignDocument(DocumentRelayMap, payload, signer)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := sampleTicket().Sign(signer)
	if err != nil {
		t.Fatal(err)
	}
	return InterchangeGrant{
		SigningKeys:    []TrustedKey{{Key: signer.Public(), NotAfter: docNow.Add(24 * time.Hour)}},
		RelayMap:       doc,
		Ticket:         ticket,
		TicketNotAfter: time.UnixMilli(sampleTicket().NotAfterMS),
	}
}

func TestInterchangeGrantRoundTrip(t *testing.T) {
	t.Parallel()
	g := sampleGrant(t)
	b, err := g.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseInterchangeGrant(b)
	if err != nil {
		t.Fatal(err)
	}
	if !got.TicketNotAfter.Equal(g.TicketNotAfter) || string(got.Ticket) != string(g.Ticket) || len(got.SigningKeys) != 1 {
		t.Fatalf("round trip: %+v", got)
	}
	ticket, err := ParseTicketUnverified(got.Ticket)
	if err != nil || ticket.Disco != sampleTicket().Disco || ticket.NotAfterMS != sampleTicket().NotAfterMS {
		t.Fatalf("ParseTicketUnverified = %+v, %v", ticket, err)
	}
	if _, err := ParseTicketUnverified(got.Ticket[:10]); err == nil {
		t.Fatal("truncated ticket parsed")
	}
	m, err := got.OpenRelayMap(docNow)
	if err != nil || m.Version != 3 {
		t.Fatalf("OpenRelayMap = %+v, %v", m, err)
	}
	// Once the key's not_after passes, the map no longer verifies.
	if _, err := got.OpenRelayMap(docNow.Add(25 * time.Hour)); err == nil {
		t.Fatal("relay map verified with an expired signing key")
	}
	forged := got
	forged.SigningKeys = []TrustedKey{{Key: otherSigningKey(t).Public(), NotAfter: docNow.Add(time.Hour)}}
	if _, err := forged.OpenRelayMap(docNow); err == nil {
		t.Fatal("relay map verified with a key that did not sign it")
	}
}

func TestInterchangeGrantRejects(t *testing.T) {
	t.Parallel()
	for i, m := range []func(*InterchangeGrant){
		func(g *InterchangeGrant) { g.SigningKeys = nil },
		func(g *InterchangeGrant) { g.SigningKeys = append(g.SigningKeys, g.SigningKeys[0]) },
		func(g *InterchangeGrant) { g.RelayMap = nil },
		func(g *InterchangeGrant) { g.Ticket = make([]byte, MaxTicketSize+1) },
		func(g *InterchangeGrant) { g.TicketNotAfter = time.UnixMilli(0) },
	} {
		g := sampleGrant(t)
		m(&g)
		if _, err := g.Marshal(); !errors.Is(err, ErrDocumentMalformed) {
			t.Errorf("mutation %d accepted", i)
		}
	}
	for _, bad := range []string{`{"version":2}`, `[]`, `{"version":1}`} {
		if _, err := ParseInterchangeGrant([]byte(bad)); err == nil {
			t.Errorf("parsed %s", bad)
		}
	}
}

func otherSigningKey(t *testing.T) key.SigningPrivate {
	t.Helper()
	k, err := key.SigningPrivateFromSeed(bytes.Repeat([]byte{0x66}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// v2Grant is sampleGrant with an MTT2 ticket for n contracts, its zone list
// and its MTT1 fallback.
func v2Grant(t *testing.T, n int) InterchangeGrant {
	t.Helper()
	g := sampleGrant(t)
	tk := sampleTicket()
	tk.Zones = contractZones(n)
	ticket, zones, err := tk.SignZones(signingKey(t))
	if err != nil {
		t.Fatal(err)
	}
	fallback := tk
	fallback.ID[0] ^= 0x80
	fallback.Zones = slices.SortedFunc(slices.Values(tk.Zones), CompareZones)[:MaxZones]
	backup, err := fallback.Sign(signingKey(t))
	if err != nil {
		t.Fatal(err)
	}
	g.Ticket, g.TicketZones, g.FallbackTicket = ticket, zones, backup
	return g
}

// TestInterchangeGrantV2: a grant with an MTT2 ticket for 10,000 contracts
// round-trips as version 2 within MaxGrantSize; one whose ticket, zones and
// fallback do not belong together is refused.
func TestInterchangeGrantV2(t *testing.T) {
	t.Parallel()
	g := v2Grant(t, 10_000)
	encoded, err := g.Marshal()
	if err != nil || len(encoded) > MaxGrantSize || !bytes.Contains(encoded, []byte(`"version":2`)) {
		t.Fatalf("Marshal: %d bytes, %v", len(encoded), err)
	}
	parsed, err := ParseInterchangeGrant(encoded)
	if err != nil || !bytes.Equal(parsed.TicketZones, g.TicketZones) || !bytes.Equal(parsed.FallbackTicket, g.FallbackTicket) {
		t.Fatalf("round trip: %v", err)
	}
	other := v2Grant(t, 50)
	v1 := sampleGrant(t)
	for name, bad := range map[string]InterchangeGrant{
		"MTT2 without zones":    {SigningKeys: g.SigningKeys, RelayMap: g.RelayMap, Ticket: g.Ticket, TicketNotAfter: g.TicketNotAfter},
		"another zone list":     {SigningKeys: g.SigningKeys, RelayMap: g.RelayMap, Ticket: g.Ticket, TicketNotAfter: g.TicketNotAfter, TicketZones: other.TicketZones},
		"MTT1 with zones":       {SigningKeys: g.SigningKeys, RelayMap: g.RelayMap, Ticket: v1.Ticket, TicketNotAfter: g.TicketNotAfter, TicketZones: g.TicketZones},
		"fallback of another":   {SigningKeys: g.SigningKeys, RelayMap: g.RelayMap, Ticket: g.Ticket, TicketNotAfter: g.TicketNotAfter, TicketZones: g.TicketZones, FallbackTicket: v1.Ticket},
		"fallback without MTT2": {SigningKeys: g.SigningKeys, RelayMap: g.RelayMap, Ticket: v1.Ticket, TicketNotAfter: g.TicketNotAfter, FallbackTicket: g.FallbackTicket},
	} {
		if _, err := bad.Marshal(); !errors.Is(err, ErrDocumentMalformed) {
			t.Errorf("%s: Marshal error = %v", name, err)
		}
	}
	// A version mismatch on the wire is refused.
	downgraded := bytes.Replace(encoded, []byte(`"version":2`), []byte(`"version":1`), 1)
	if _, err := ParseInterchangeGrant(downgraded); !errors.Is(err, ErrDocumentMalformed) {
		t.Fatalf("version 1 with zones: %v", err)
	}
}

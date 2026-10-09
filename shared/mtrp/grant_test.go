package mtrp

import (
	"bytes"
	"errors"
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

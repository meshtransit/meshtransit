package mtrp

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/shared/key"
)

var docNow = time.UnixMilli(1760000000000)

func TestSignedDocument(t *testing.T) {
	t.Parallel()
	signer := signingKey(t)
	keys := NewStaticKeys(signer.Public())
	doc, err := SignDocument(DocumentRelayState, []byte(`{"x":1}`), signer)
	if err != nil {
		t.Fatal(err)
	}
	payload, id, err := OpenDocument(doc, DocumentRelayState, keys)
	if err != nil || !bytes.Equal(payload, []byte(`{"x":1}`)) || id != signer.Public().ID() {
		t.Fatalf("OpenDocument = %q, %v", payload, err)
	}

	// A relay-state signature is not a relay-map signature.
	asMap := bytes.Clone(doc)
	asMap[5] = byte(DocumentRelayMap)
	if _, _, err := OpenDocument(asMap, DocumentRelayMap, keys); !errors.Is(err, ErrDocumentSignature) {
		t.Fatalf("kind confusion: %v", err)
	}
	tampered := bytes.Clone(doc)
	tampered[documentHeaderSize] ^= 1
	if _, _, err := OpenDocument(tampered, DocumentRelayState, keys); !errors.Is(err, ErrDocumentSignature) {
		t.Fatalf("tampered payload: %v", err)
	}
	other, _ := key.SigningPrivateFromSeed(bytes.Repeat([]byte{0x77}, 32))
	if _, _, err := OpenDocument(doc, DocumentRelayState, NewStaticKeys(other.Public())); !errors.Is(err, ErrDocumentSignature) {
		t.Fatalf("unknown key: %v", err)
	}
	for _, bad := range [][]byte{nil, doc[:20], append(bytes.Clone(doc), 0)} {
		if _, _, err := OpenDocument(bad, DocumentRelayState, keys); err == nil {
			t.Error("malformed document accepted")
		}
	}
	if _, err := SignDocument(DocumentKind(9), []byte("x"), signer); err == nil {
		t.Fatal("unknown kind signed")
	}
}

func sampleState(t testing.TB) RelayState {
	t.Helper()
	other, _ := key.SigningPrivateFromSeed(bytes.Repeat([]byte{0x43}, 32))
	ticketID := sampleTicket().ID
	revokedNode := key.NodePublic{0x99}
	return RelayState{
		Sequence: 7, IssuedAt: docNow, ExpiresAt: docNow.Add(10 * time.Minute),
		SigningKeys: []TrustedKey{
			{Key: signingKey(t).Public(), NotAfter: docNow.Add(24 * time.Hour)},
			{Key: other.Public(), NotAfter: docNow.Add(-time.Minute)}, // already retired
		},
		Tickets: []RevocationID{RevocationHash(RevokeTicket, ticketID[:])},
		Nodes:   []RevocationID{RevocationHash(RevokeNode, revokedNode[:])},
		Drain:   []key.RelayPublic{{0x01}},
	}
}

func TestRelayStateRoundTrip(t *testing.T) {
	t.Parallel()
	s := sampleState(t)
	payload, err := s.Payload()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRelayState(payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sequence != 7 || !got.ExpiresAt.Equal(s.ExpiresAt) || len(got.SigningKeys) != 2 || got.Drain[0] != s.Drain[0] {
		t.Fatalf("round trip: %+v", got)
	}
	keys, err := got.TrustedKeySet(docNow)
	if err != nil || len(keys) != 1 {
		t.Fatalf("trusted keys at now = %v, %v (the retired key must not count)", keys, err)
	}

	set := NewRevocationSet(got)
	revokedTicket := sampleTicket()
	if !set.Revoked(revokedTicket) {
		t.Fatal("revoked ticket id not matched")
	}
	byNode := sampleTicket()
	byNode.ID, byNode.Node = [16]byte{0xee}, key.NodePublic{0x99}
	if !set.Revoked(byNode) {
		t.Fatal("revoked node not matched")
	}
	clean := sampleTicket()
	clean.ID = [16]byte{0xfe}
	if set.Revoked(clean) || set.Len() != 2 {
		t.Fatal("unrevoked ticket matched")
	}
}

func TestRelayStateRejects(t *testing.T) {
	t.Parallel()
	mutate := []func(*RelayState){
		func(s *RelayState) { s.Sequence = 0 },
		func(s *RelayState) { s.ExpiresAt = s.IssuedAt },
		func(s *RelayState) { s.ExpiresAt = s.IssuedAt.Add(2 * time.Hour) },
		func(s *RelayState) { s.SigningKeys = nil },
		func(s *RelayState) { s.SigningKeys = append(s.SigningKeys, s.SigningKeys[0]) },
		func(s *RelayState) { s.Drain = []key.RelayPublic{{}} },
	}
	for i, m := range mutate {
		s := sampleState(t)
		m(&s)
		if _, err := s.Payload(); !errors.Is(err, ErrDocumentMalformed) {
			t.Errorf("mutation %d accepted", i)
		}
	}
	for _, bad := range []string{
		`{"version":2}`,
		`{"version":1,"sequence":1,"issued_at_ms":1,"expires_at_ms":2,"signing_keys":[],"revoked":{}}`,
		`{"version":1,"sequence":1,"issued_at_ms":1,"expires_at_ms":2,"signing_keys":[{"key":"mtsign:00","not_after_ms":3}],"revoked":{}}`,
		`{"version":1,"revoked":{"tickets":["zz"]}}`,
		`not json`,
	} {
		if _, err := ParseRelayState([]byte(bad)); err == nil {
			t.Errorf("parsed %s", bad)
		}
	}
}

func sampleMap() RelayMap {
	return RelayMap{
		Version: 3, ExpiresAt: docNow.Add(7 * 24 * time.Hour),
		Regions: []RelayRegion{{
			ID: 1, Code: "sgp", Name: "Singapore",
			Nodes: []RelayNode{{
				Name: "sgp1", HostName: "relay-sgp1.meshtransit.net", IPv4: netip.MustParseAddr("18.142.253.199"),
				Key: key.RelayPublic{0x18}, UDPPort: 3479, TLSPort: 443, STUNPort: 3478, STUNAltPort: 3480, Weight: 100,
			}},
		}},
	}
}

func TestRelayMapRoundTrip(t *testing.T) {
	t.Parallel()
	m := sampleMap()
	payload, err := m.Payload(docNow)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := SignDocument(DocumentRelayMap, payload, signingKey(t))
	if err != nil {
		t.Fatal(err)
	}
	opened, _, err := OpenDocument(doc, DocumentRelayMap, NewStaticKeys(signingKey(t).Public()))
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRelayMap(opened, docNow)
	if err != nil {
		t.Fatal(err)
	}
	n := got.Regions[0].Nodes[0]
	if got.Version != 3 || n.HostName != "relay-sgp1.meshtransit.net" || n.IPv4 != m.Regions[0].Nodes[0].IPv4 || n.STUNAltPort != 3480 {
		t.Fatalf("round trip: %+v", got)
	}
	if _, err := ParseRelayMap(opened, m.ExpiresAt); err == nil {
		t.Fatal("expired map accepted")
	}
}

func TestRelayMapRejects(t *testing.T) {
	t.Parallel()
	mutate := []func(*RelayMap){
		func(m *RelayMap) { m.Version = 0 },
		func(m *RelayMap) { m.ExpiresAt = docNow.Add(60 * 24 * time.Hour) },
		func(m *RelayMap) { m.Regions = nil },
		func(m *RelayMap) { m.Regions[0].Code = "SGP" },
		func(m *RelayMap) { m.Regions = append(m.Regions, m.Regions[0]) },
		func(m *RelayMap) { m.Regions[0].Nodes[0].HostName = "not a host" },
		func(m *RelayMap) { m.Regions[0].Nodes[0].Key = key.RelayPublic{} },
		func(m *RelayMap) { m.Regions[0].Nodes[0].IPv4 = netip.Addr{} },
		func(m *RelayMap) { m.Regions[0].Nodes[0].IPv4 = netip.MustParseAddr("2001:db8::1") },
		func(m *RelayMap) { m.Regions[0].Nodes[0].UDPPort = 0 },
		func(m *RelayMap) { m.Regions[0].Nodes[0].Weight = 0 },
		func(m *RelayMap) {
			n := m.Regions[0].Nodes[0]
			m.Regions = append(m.Regions, RelayRegion{ID: 2, Code: "hkg", Name: "Hong Kong", Nodes: []RelayNode{n}})
		},
	}
	for i, mut := range mutate {
		m := sampleMap()
		m.Regions = append([]RelayRegion(nil), m.Regions...)
		m.Regions[0].Nodes = append([]RelayNode(nil), m.Regions[0].Nodes...)
		mut(&m)
		if _, err := m.Payload(docNow); !errors.Is(err, ErrDocumentMalformed) {
			t.Errorf("mutation %d accepted", i)
		}
	}
}

func FuzzOpenDocument(f *testing.F) {
	signer := signingKey(f)
	keys := NewStaticKeys(signer.Public())
	doc, _ := SignDocument(DocumentRelayState, []byte("{}"), signer)
	f.Add(doc)
	f.Fuzz(func(t *testing.T, b []byte) {
		if payload, _, err := OpenDocument(b, DocumentRelayState, keys); err == nil {
			_, _ = ParseRelayState(payload)
		}
	})
}

func FuzzParseRelayPayloads(f *testing.F) {
	s := sampleState(f)
	p, _ := s.Payload()
	f.Add(p)
	m, _ := sampleMap().Payload(docNow)
	f.Add(m)
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ParseRelayState(b)
		_, _ = ParseRelayMap(b, docNow)
	})
}

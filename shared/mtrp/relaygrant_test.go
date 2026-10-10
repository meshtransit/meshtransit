package mtrp

import (
	"errors"
	"testing"
	"time"

	"meshtransit.net/shared/key"
)

func grantFixture(t *testing.T, relay key.RelayPublic, now time.Time) RelayGrant {
	t.Helper()
	return RelayGrant{
		Relay: relay, Sequence: 7, IssuedAt: now, ExpiresAt: now.Add(10 * time.Minute),
		Networks: [][16]byte{{0x01, 0x89}, {0x01, 0x8a, 0xff}},
	}
}

func TestRelayGrantRoundTripAndSeal(t *testing.T) {
	t.Parallel()
	now := time.UnixMilli(1_800_000_000_000)
	relay, err := key.NewRelayPrivate()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := key.NewSigningPrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	grant := grantFixture(t, relay.Public(), now)
	payload, err := grant.Payload()
	if err != nil {
		t.Fatal(err)
	}
	document, err := SignDocument(DocumentRelayGrant, payload, signer)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealRelayGrant(document, relay.Public(), nil)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenRelayGrant(sealed, relay)
	if err != nil {
		t.Fatal(err)
	}
	inner, _, err := OpenDocument(opened, DocumentRelayGrant, NewStaticKeys(signer.Public()))
	if err != nil {
		t.Fatalf("open document: %v", err)
	}
	parsed, err := ParseRelayGrant(inner, relay.Public(), now)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Serves([16]byte{0x01, 0x89}) || parsed.Serves([16]byte{0x02}) || parsed.Sequence != 7 {
		t.Fatalf("parsed %+v", parsed)
	}

	// Another relay cannot read it, and a changed byte breaks it.
	other, _ := key.NewRelayPrivate()
	if _, err := OpenRelayGrant(sealed, other); !errors.Is(err, ErrGrantSealed) {
		t.Fatalf("another relay opened it: %v", err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 1
	if _, err := OpenRelayGrant(tampered, relay); !errors.Is(err, ErrGrantSealed) {
		t.Fatalf("tampered grant opened: %v", err)
	}
	// A grant for another relay or an expired one is refused.
	if _, err := ParseRelayGrant(inner, other.Public(), now); err == nil {
		t.Fatal("grant for another relay accepted")
	}
	if _, err := ParseRelayGrant(inner, relay.Public(), now.Add(time.Hour)); err == nil {
		t.Fatal("expired grant accepted")
	}
}

func TestRelayGrantValidation(t *testing.T) {
	t.Parallel()
	now := time.UnixMilli(1_800_000_000_000)
	relay, _ := key.NewRelayPrivate()
	for name, mutate := range map[string]func(*RelayGrant){
		"no relay":     func(g *RelayGrant) { g.Relay = key.RelayPublic{} },
		"no sequence":  func(g *RelayGrant) { g.Sequence = 0 },
		"too long":     func(g *RelayGrant) { g.ExpiresAt = g.IssuedAt.Add(2 * time.Hour) },
		"unsorted":     func(g *RelayGrant) { g.Networks[0], g.Networks[1] = g.Networks[1], g.Networks[0] },
		"zero network": func(g *RelayGrant) { g.Networks = [][16]byte{{}} },
		"duplicate":    func(g *RelayGrant) { g.Networks = [][16]byte{{1}, {1}} },
	} {
		grant := grantFixture(t, relay.Public(), now)
		mutate(&grant)
		if _, err := grant.Payload(); !errors.Is(err, ErrDocumentMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
	empty := grantFixture(t, relay.Public(), now)
	empty.Networks = nil
	payload, err := empty.Payload()
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseRelayGrant(payload, relay.Public(), now); err != nil || len(parsed.Networks) != 0 {
		t.Fatalf("an empty grant: %+v %v", parsed, err)
	}
}

func TestUUIDText(t *testing.T) {
	t.Parallel()
	id := [16]byte{0x01, 0x89, 0x0f, 0x00, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0x02, 0x01}
	text := formatUUID(id)
	if text != "01890f00-0000-7000-8000-000000000201" {
		t.Fatalf("formatted %s", text)
	}
	if parsed, ok := parseUUID(text); !ok || parsed != id {
		t.Fatalf("parsed %x %v", parsed, ok)
	}
	for _, bad := range []string{"", "01890F00-0000-7000-8000-000000000201", "01890f00x0000-7000-8000-000000000201", text + "0"} {
		if _, ok := parseUUID(bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}

func FuzzParseRelayGrant(f *testing.F) {
	relay, _ := key.NewRelayPrivate()
	now := time.UnixMilli(1_800_000_000_000)
	seed, _ := grantFixture(&testing.T{}, relay.Public(), now).Payload()
	f.Add(seed)
	f.Fuzz(func(t *testing.T, payload []byte) {
		grant, err := ParseRelayGrant(payload, relay.Public(), now)
		if err == nil {
			if _, err := grant.Payload(); err != nil {
				t.Fatalf("a parsed grant does not encode: %v", err)
			}
		}
		_, _ = OpenRelayGrant(payload, relay)
	})
}

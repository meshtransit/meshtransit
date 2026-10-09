package ts2021

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

	"tailscale.com/tailcfg"

	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

func grantCapability(t *testing.T, signer key.SigningPrivate, version uint64, expires, now time.Time, disco key.DiscoPublic) tailcfg.NodeCapMap {
	t.Helper()
	payload, err := mtrp.RelayMap{Version: version, ExpiresAt: expires, Regions: []mtrp.RelayRegion{{
		ID: 1, Code: "sgp", Name: "Singapore", Nodes: []mtrp.RelayNode{{
			Name: "sgp1", HostName: "relay-sgp1.example.com", IPv4: netip.MustParseAddr("18.142.253.199"),
			Key: key.RelayPublic{0x18}, UDPPort: 3479, TLSPort: 443, STUNPort: 3478, Weight: 100,
		}},
	}}}.Payload(now)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := mtrp.SignDocument(mtrp.DocumentRelayMap, payload, signer)
	if err != nil {
		t.Fatal(err)
	}
	ticket := mtrp.Ticket{
		ID: [16]byte{1, 2, 3}, IssuedAtMS: now.UnixMilli(), NotAfterMS: now.Add(15 * time.Minute).UnixMilli(),
		Node: key.NodePublic{1}, Disco: disco, Deployment: [16]byte{1},
		Zones: []mtrp.Zone{{Kind: mtrp.ZoneNetwork, ID: [16]byte{2}}},
	}
	signed, err := ticket.Sign(signer)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := mtrp.InterchangeGrant{
		SigningKeys: []mtrp.TrustedKey{{Key: signer.Public(), NotAfter: now.Add(24 * time.Hour)}},
		RelayMap:    doc, Ticket: signed, TicketNotAfter: ticket.NotAfter(),
	}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return tailcfg.NodeCapMap{interchangeCapability: []tailcfg.RawMessage{tailcfg.RawMessage(encoded)}}
}

func TestMapAccumulatorHoldsInterchangeGrant(t *testing.T) {
	t.Parallel()

	signer, err := key.SigningPrivateFromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	disco := key.DiscoPublic{0xd1}
	self := testWireNode(1, 1)
	self.CapMap = grantCapability(t, signer, 2, now.Add(7*24*time.Hour), now, disco)
	accumulator := newMapAccumulator()
	snapshot, changed, err := accumulator.apply(tailcfg.MapResponse{Node: self, Peers: []*tailcfg.Node{testWireNode(2, 2)}}, now)
	if err != nil || !changed {
		t.Fatalf("apply() = %v, %v", changed, err)
	}
	grant := snapshot.Interchange
	if grant == nil || grant.MapVersion != 2 || grant.TicketDisco != disco || len(grant.Ticket) == 0 {
		t.Fatalf("snapshot grant = %+v", grant)
	}
	region := snapshot.Relays[1]
	if len(snapshot.Relays) != 1 || len(region.Nodes) != 1 || region.Nodes[0].RelayKey != (key.RelayPublic{0x18}) ||
		region.Nodes[0].UDPPort != 3479 || region.Nodes[0].RelayPort != 443 || region.Nodes[0].STUNPort != 3478 {
		t.Fatalf("relay regions = %+v", snapshot.Relays)
	}

	// An entry without the capability keeps the grant; an older relay map
	// and a grant signed by an unknown key are ignored.
	plain := testWireNode(1, 1)
	plain.Name = "renamed.example.mesh."
	if snapshot, _, err := accumulator.apply(tailcfg.MapResponse{Node: plain}, now); err != nil ||
		(snapshot.Interchange != nil && snapshot.Interchange.MapVersion != 2) {
		t.Fatalf("grant lost: %v", err)
	}
	if accumulator.interchange == nil || accumulator.interchange.relayMap.Version != 2 {
		t.Fatal("grant dropped by an entry without it")
	}
	older := testWireNode(1, 1)
	older.CapMap = grantCapability(t, signer, 1, now.Add(7*24*time.Hour), now, disco)
	if _, _, err := accumulator.apply(tailcfg.MapResponse{Node: older}, now); err != nil {
		t.Fatal(err)
	}
	if accumulator.interchange.relayMap.Version != 2 {
		t.Fatal("older relay map replaced the held one")
	}

	// A renewal re-signs the same map with a later expiry and a new ticket.
	renewed := testWireNode(1, 1)
	renewed.CapMap = grantCapability(t, signer, 2, now.Add(8*24*time.Hour), now, disco)
	snapshot, changed, err = accumulator.apply(tailcfg.MapResponse{Node: renewed}, now)
	if err != nil || !changed || snapshot.Interchange == nil || !snapshot.Interchange.MapExpiresAt.Equal(now.Add(8*24*time.Hour).Truncate(time.Millisecond)) {
		t.Fatalf("renewal not applied: changed=%v err=%v grant=%+v", changed, err, snapshot.Interchange)
	}
}

func TestParseInterchangeRejectsTampering(t *testing.T) {
	t.Parallel()

	signer, err := key.SigningPrivateFromSeed(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	node := &tailcfg.Node{CapMap: grantCapability(t, signer, 2, now.Add(time.Hour), now, key.DiscoPublic{1})}
	if _, present, err := parseInterchange(node, now); !present || err != nil {
		t.Fatalf("valid grant rejected: %v", err)
	}
	value := []byte(node.CapMap[interchangeCapability][0])
	tampered := bytes.Replace(value, []byte(`"version":1`), []byte(`"version":2`), 1)
	node.CapMap[interchangeCapability] = []tailcfg.RawMessage{tailcfg.RawMessage(tampered)}
	if _, present, err := parseInterchange(node, now); !present || err == nil {
		t.Fatal("tampered grant accepted")
	}
	if _, present, _ := parseInterchange(&tailcfg.Node{}, now); present {
		t.Fatal("absent grant reported present")
	}
}

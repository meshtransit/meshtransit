package relayauthority

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

func mustParse[T any](t *testing.T, parse func(string) (T, error), value string) T {
	t.Helper()
	parsed, err := parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestIssuerGrantsVerifiableTicket(t *testing.T) {
	t.Parallel()

	signer := signer(t, 1)
	c := newClock(t0)
	m := testMap(t)
	p := newPublisher(t, c, Options{Signer: signer, Map: &m})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	dep := mustParse(t, deployment.ParseID, "01890f00-0000-7000-8000-000000000123")
	issuer, err := NewIssuer(p, dep)
	if err != nil {
		t.Fatal(err)
	}
	networkID := mustParse(t, network.ParseID, "01890f00-0000-7000-8000-000000000201")
	contract := mustParse(t, sharing.ParseContractID, "01890f00-0000-7000-8000-000000000301")
	request := mapsession.RelayGrantRequest{
		NodeKey: node.Key{0x10}, DiscoveryKey: node.DiscoveryKey{0x20},
		Network: networkID, TrustContracts: []sharing.ContractID{contract},
		NotAfter: t0.Add(24 * time.Hour),
	}
	grant, err := issuer.GrantRelayAccess(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !grant.RenewAt().Equal(t0.Add(TicketLifetime - 5*time.Minute)) {
		t.Fatalf("renew at %v", grant.RenewAt())
	}
	decoded, err := mtrp.ParseInterchangeGrant(grant.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if relayMap, err := decoded.OpenRelayMap(t0); err != nil || relayMap.Version != MapVersion(3, 0) {
		t.Fatalf("grant relay map = %+v, %v", relayMap, err)
	}
	verifier := mtrp.Verifier{Keys: mtrp.NewStaticKeys(signer.Public()), Now: c.now}
	ticket, err := verifier.Verify(decoded.Ticket)
	if err != nil {
		t.Fatal(err)
	}
	wantZones := []mtrp.Zone{
		{Kind: mtrp.ZoneNetwork, ID: networkID.Bytes()},
		{Kind: mtrp.ZoneTrustContract, ID: contract.Bytes()},
	}
	if ticket.Node != (key.NodePublic{0x10}) || ticket.Disco != (key.DiscoPublic{0x20}) ||
		ticket.Deployment != dep.Bytes() || len(ticket.Zones) != 2 || ticket.Zones[0] != wantZones[0] ||
		ticket.Zones[1] != wantZones[1] || !ticket.NotAfter().Equal(t0.Add(TicketLifetime)) ||
		!decoded.TicketNotAfter.Equal(ticket.NotAfter()) {
		t.Fatalf("ticket = %+v", ticket)
	}

	// A ticket never outlives the node's authority, and none is issued when
	// that ends within a minute.
	request.NotAfter = t0.Add(4 * time.Minute)
	short, err := issuer.GrantRelayAccess(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, _ = mtrp.ParseInterchangeGrant(short.Payload())
	if !decoded.TicketNotAfter.Equal(t0.Add(4 * time.Minute)) {
		t.Fatalf("clamped expiry %v", decoded.TicketNotAfter)
	}
	request.NotAfter = t0.Add(30 * time.Second)
	if _, err := issuer.GrantRelayAccess(t.Context(), request); !errors.Is(err, ErrAuthorityEnding) {
		t.Fatalf("ending authority: %v", err)
	}
}

func TestIssuerNeedsRelayMap(t *testing.T) {
	t.Parallel()

	p := newPublisher(t, newClock(t0), Options{Signer: signer(t, 1)})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	issuer, err := NewIssuer(p, mustParse(t, deployment.ParseID, "01890f00-0000-7000-8000-000000000123"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.GrantRelayAccess(t.Context(), mapsession.RelayGrantRequest{NotAfter: t0.Add(time.Hour)}); !errors.Is(err, ErrNoRelayMap) {
		t.Fatalf("grant without map: %v", err)
	}
	if _, err := NewIssuer(nil, deployment.ID{}); err == nil {
		t.Fatal("invalid issuer accepted")
	}
}

func TestDirectoryFromRelayMap(t *testing.T) {
	t.Parallel()

	directory, err := Directory(testMap(t))
	if err != nil {
		t.Fatal(err)
	}
	region, found := directory.Region(1)
	if !found || directory.Revision() != 3 || len(region.Nodes()) != 1 {
		t.Fatalf("directory = %+v", directory)
	}
	node := region.Nodes()[0]
	if node.HostName() != "relay-sgp1.meshtransit.net" || node.IPv4() != "18.142.253.199" ||
		node.IPv6() != "none" || node.RelayPort() != 443 || node.STUNPort() != 3478 {
		t.Fatalf("node = %s %s %s %d %d", node.HostName(), node.IPv4(), node.IPv6(), node.RelayPort(), node.STUNPort())
	}
}

// TestIssuerSignsMTT2ForManyContracts: past MaxZones zones the issuer signs
// an MTT2 ticket and ships its zone list in the grant; the list completes
// the ticket the relay verifies. Fewer zones keep MTT1.
func TestIssuerSignsMTT2ForManyContracts(t *testing.T) {
	t.Parallel()
	signer := signer(t, 1)
	c := newClock(t0)
	m := testMap(t)
	p := newPublisher(t, c, Options{Signer: signer, Map: &m})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	issuer, err := NewIssuer(p, mustParse(t, deployment.ParseID, "01890f00-0000-7000-8000-000000000123"))
	if err != nil {
		t.Fatal(err)
	}
	networkID := mustParse(t, network.ParseID, "01890f00-0000-7000-8000-000000000201")
	contracts := make([]sharing.ContractID, 0, 2*mtrp.MaxZones)
	for i := range 2 * mtrp.MaxZones {
		contracts = append(contracts, mustParse(t, sharing.ParseContractID,
			fmt.Sprintf("01890f00-0000-7000-8000-%012x", 0x300+i)))
	}
	verifier := mtrp.Verifier{Keys: mtrp.NewStaticKeys(signer.Public()), Now: c.now}
	for _, count := range []int{1, mtrp.MaxZones - 1, mtrp.MaxZones, len(contracts)} {
		grant, err := issuer.GrantRelayAccess(t.Context(), mapsession.RelayGrantRequest{
			NodeKey: node.Key{0x10}, DiscoveryKey: node.DiscoveryKey{0x20}, Network: networkID,
			TrustContracts: contracts[:count], NotAfter: t0.Add(24 * time.Hour),
		})
		if err != nil {
			t.Fatalf("%d contracts: %v", count, err)
		}
		decoded, err := mtrp.ParseInterchangeGrant(grant.Payload())
		if err != nil {
			t.Fatalf("%d contracts: %v", count, err)
		}
		ticket, err := verifier.Verify(decoded.Ticket)
		if err != nil {
			t.Fatalf("%d contracts: %v", count, err)
		}
		v2 := count+1 > mtrp.MaxZones
		if ticket.IsV2() != v2 || (len(decoded.TicketZones) != 0) != v2 {
			t.Fatalf("%d contracts: MTT2 %v, zone list %d bytes", count, ticket.IsV2(), len(decoded.TicketZones))
		}
		complete, err := mtrp.CompleteTicket(decoded.Ticket, decoded.TicketZones)
		if err != nil || len(complete.Zones) != count+1 || complete.Zones[0].Kind != mtrp.ZoneNetwork {
			t.Fatalf("%d contracts: complete ticket %d zones, %v", count, len(complete.Zones), err)
		}
		// MTT2 comes with a verifiable MTT1 fallback naming its inline zones.
		if (len(decoded.FallbackTicket) != 0) != v2 {
			t.Fatalf("%d contracts: fallback %d bytes", count, len(decoded.FallbackTicket))
		}
		if v2 {
			fallback, err := verifier.Verify(decoded.FallbackTicket)
			if err != nil || fallback.IsV2() || len(fallback.Zones) != mtrp.MaxZones || fallback.ID == ticket.ID ||
				mtrp.CheckFallbackTicket(decoded.Ticket, decoded.FallbackTicket) != nil {
				t.Fatalf("%d contracts: fallback %+v, %v", count, fallback, err)
			}
		}
	}
}

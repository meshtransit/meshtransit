package dataplane

import (
	"testing"
	"time"

	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/relay"
	"meshtransit.net/shared/key"
)

func TestRelayCredentialsRequireMatchingLiveTicket(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_760_000_000, 0)
	credentials := newRelayCredentials(func() time.Time { return now })
	if _, _, ok := credentials.RelayCredentials(); ok {
		t.Fatal("credentials without identity or ticket")
	}
	disco, err := key.NewDiscoPrivate()
	if err != nil {
		t.Fatal(err)
	}
	credentials.setIdentity(disco)
	credentials.setGrant(&networkmap.Interchange{
		Ticket: []byte("ticket"), TicketNotAfter: now.Add(time.Minute), TicketDisco: disco.Public(),
	})
	gotDisco, ticket, ok := credentials.RelayCredentials()
	if !ok || gotDisco.Public() != disco.Public() || string(ticket) != "ticket" {
		t.Fatal("matching live ticket refused")
	}
	credentials.setGrant(nil) // a map without a grant keeps the ticket
	if _, _, ok := credentials.RelayCredentials(); !ok {
		t.Fatal("ticket dropped by a map without a grant")
	}

	// A ticket for another disco key (issued before this session's key
	// reached Core) is not presented.
	other, err := key.NewDiscoPrivate()
	if err != nil {
		t.Fatal(err)
	}
	credentials.setIdentity(other)
	if _, _, ok := credentials.RelayCredentials(); ok {
		t.Fatal("ticket for another disco key presented")
	}
	credentials.setIdentity(disco)
	now = now.Add(2 * time.Minute)
	if _, _, ok := credentials.RelayCredentials(); ok {
		t.Fatal("expired ticket presented")
	}
}

func TestRelayConfigCarriesInterchangeNodes(t *testing.T) {
	t.Parallel()

	regions := map[int]networkmap.RelayRegion{1: {ID: 1, Code: "sgp", Name: "Singapore", Nodes: []networkmap.RelayNode{{
		Name: "sgp1", HostName: "relay-sgp1.example.com", IPv4: "18.142.253.199",
		RelayPort: 443, UDPPort: 3479, RelayKey: [32]byte{0x18},
	}}}}
	region, ok := usableRelayRegion(regions, 1)
	if !ok || region.Nodes[0].RelayKey != ([32]byte{0x18}) || region.Nodes[0].UDPPort != 3479 || region.Nodes[0].Port != 443 {
		t.Fatalf("usableRelayRegion = %+v", region)
	}
	if !usesInterchange(relay.Config{Regions: map[int]relay.Region{1: region}}) {
		t.Fatal("Interchange node not recognised")
	}
	legacy := region
	legacy.Nodes = []relay.Node{{Name: "1a", HostName: "derp.example.com", Port: 443}}
	if usesInterchange(relay.Config{Regions: map[int]relay.Region{1: legacy}}) {
		t.Fatal("legacy node taken for Interchange")
	}
}

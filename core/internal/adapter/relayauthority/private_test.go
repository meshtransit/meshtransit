package relayauthority

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"testing"

	"meshtransit.net/core/internal/domain/interchange"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/platform/clientip"
	"meshtransit.net/shared/key"
	"meshtransit.net/shared/mtrp"
)

// staticPrivate serves a fixed Private Interchange directory.
type staticPrivate struct {
	mu        sync.Mutex
	directory interchange.Directory
}

func (s *staticPrivate) ReadPrivateInterchanges(context.Context) (interchange.Directory, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.directory, nil
}

func (s *staticPrivate) set(directory interchange.Directory) {
	s.mu.Lock()
	s.directory = directory
	s.mu.Unlock()
}

func mustNetworkID(t *testing.T, text string) network.ID {
	t.Helper()
	id, err := network.ParseID(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func officeRelay(t *testing.T, relayKey key.RelayPublic, networks ...network.ID) interchange.Interchange {
	t.Helper()
	return interchange.Interchange{RegionID: 1000, Spec: interchange.Spec{Name: "Office relay", RegionCode: "office",
		HostName: "relay.office.example.com", IPv4: netip.MustParseAddr("203.0.113.40"), RelayKey: relayKey,
		UDPPort: 3479, TLSPort: 443, STUNPort: 3478, Networks: interchange.SortNetworks(networks)}}
}

func TestNetworkMapAddsPreferredPrivateRegions(t *testing.T) {
	t.Parallel()
	shared := testMap(t)
	office := officeRelay(t, key.RelayPublic{0x40})
	m := NetworkMap(shared, []interchange.Interchange{office}, 1_760_000_000)
	if m.Version != MapVersion(3, 1_760_000_000) || len(m.Regions) != 2 {
		t.Fatalf("map %+v", m)
	}
	private := m.Regions[1]
	if !private.Preferred || private.ID != 1000 || private.Code != "office" || private.Nodes[0].Key != office.Spec.RelayKey {
		t.Fatalf("private region %+v", private)
	}
	if _, err := m.Payload(t0); err != nil {
		t.Fatalf("the Network map does not validate: %v", err)
	}
	// A private relay that clashes with the shared map is left out.
	clash := office
	clash.Spec.RegionCode = "sgp"
	if got := NetworkMap(shared, []interchange.Interchange{clash}, 1); len(got.Regions) != 1 {
		t.Fatalf("a clashing region was added: %+v", got.Regions)
	}
	if MapVersion(3, 5) <= MapVersion(3, 4) || MapVersion(4, 0) <= MapVersion(3, 1<<31) {
		t.Fatal("map versions do not grow")
	}
}

func TestPublisherServesPrivateInterchange(t *testing.T) {
	t.Parallel()
	c := newClock(t0)
	m := testMap(t)
	signing := signer(t, 1)
	relayPrivate, err := key.NewRelayPrivate()
	if err != nil {
		t.Fatal(err)
	}
	granted := mustNetworkID(t, "01890f00-0000-7000-8000-000000000201")
	other := mustNetworkID(t, "01890f00-0000-7000-8000-000000000202")
	source := &staticPrivate{}
	source.set(interchange.Directory{Revision: 1_760_000_000,
		Relays: []interchange.Interchange{officeRelay(t, relayPrivate.Public(), granted)}})
	p := newPublisher(t, c, Options{Signer: signing, Map: &m, Private: source})
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}

	// The granted Network's map has the preferred private region; another
	// Network's does not; their directories match their maps.
	open := func(id network.ID) mtrp.RelayMap {
		doc, _, err := p.mapForNetwork(id)
		if err != nil {
			t.Fatal(err)
		}
		payload, _, err := mtrp.OpenDocument(doc.body, mtrp.DocumentRelayMap, mtrp.NewStaticKeys(signing.Public()))
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := mtrp.ParseRelayMap(payload, t0)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	if regions := open(granted).Regions; len(regions) != 2 || !regions[1].Preferred {
		t.Fatalf("granted Network regions %+v", regions)
	}
	if regions := open(other).Regions; len(regions) != 1 {
		t.Fatalf("other Network regions %+v", regions)
	}
	if directory, err := p.DirectoryFor(granted); err != nil || len(directory.Regions()) != 2 {
		t.Fatalf("granted directory %+v %v", directory, err)
	}
	_, grantedKey, _ := p.mapForNetwork(granted)
	if !p.RelayMapCurrent(granted, grantedKey) {
		t.Fatal("a current map reads as outdated")
	}
	if !p.Uses("sgp", key.RelayPublic{}) || p.Uses("office", key.RelayPublic{0x99}) {
		t.Fatal("shared map clash detection is wrong")
	}

	// The relay gets its grant, sealed so only it can read it.
	handler := NewHandler(p, clientip.Resolver{})
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		GrantPath+"?relay="+relayPrivate.Public().String(), nil)
	request.RemoteAddr = "198.51.100.9:4000"
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("grant status %d", recorder.Code)
	}
	sealed, _ := io.ReadAll(recorder.Body)
	document, err := mtrp.OpenRelayGrant(sealed, relayPrivate)
	if err != nil {
		t.Fatal(err)
	}
	payload, _, err := mtrp.OpenDocument(document, mtrp.DocumentRelayGrant, mtrp.NewStaticKeys(signing.Public()))
	if err != nil {
		t.Fatal(err)
	}
	grant, err := mtrp.ParseRelayGrant(payload, relayPrivate.Public(), t0)
	if err != nil || !grant.Serves(granted.Bytes()) || grant.Serves(other.Bytes()) {
		t.Fatalf("grant %+v %v", grant, err)
	}
	for name, target := range map[string]string{
		"unknown relay": GrantPath + "?relay=" + key.RelayPublic{0x77}.String(),
		"no relay":      GrantPath,
		"bad relay":     GrantPath + "?relay=mtrelay:xyz",
	} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		request.RemoteAddr = "198.51.100.9:4000"
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code == http.StatusOK {
			t.Errorf("%s: served a grant", name)
		}
	}

	// Removing the relay from the Network makes the old map outdated, in the
	// next window.
	source.set(interchange.Directory{Revision: 1_760_000_100,
		Relays: []interchange.Interchange{officeRelay(t, relayPrivate.Public())}})
	c.advance(RefreshInterval)
	if err := p.refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	if p.RelayMapCurrent(granted, grantedKey) {
		t.Fatal("a map with a removed relay still reads as current")
	}
	if regions := open(granted).Regions; len(regions) != 1 {
		t.Fatalf("the removed relay is still in the map: %+v", regions)
	}
}

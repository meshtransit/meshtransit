package interchange

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
	"meshtransit.net/shared/key"
)

func mustNetwork(t *testing.T, text string) network.ID {
	t.Helper()
	id, err := network.ParseID(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func validSpec(t *testing.T) Spec {
	t.Helper()
	return Spec{Name: "Office relay", RegionCode: "office-hn", HostName: "relay.office.example.com",
		IPv4: netip.MustParseAddr("203.0.113.40"), IPv6: netip.MustParseAddr("2001:db8:40::1"),
		RelayKey: key.RelayPublic{1}, UDPPort: 3479, TLSPort: 443, STUNPort: 3478,
		Networks: SortNetworks([]network.ID{
			mustNetwork(t, "01890f00-0000-7000-8000-000000000203"),
			mustNetwork(t, "01890f00-0000-7000-8000-000000000201"),
		})}
}

func TestSpecValidation(t *testing.T) {
	t.Parallel()
	if !validSpec(t).IsValid() {
		t.Fatal("a valid spec was refused")
	}
	for name, mutate := range map[string]func(*Spec){
		"blank name":      func(s *Spec) { s.Name = " " },
		"padded name":     func(s *Spec) { s.Name = " Office" },
		"upper code":      func(s *Spec) { s.RegionCode = "Office" },
		"host by address": func(s *Spec) { s.HostName = "203.0.113.40" },
		"no address":      func(s *Spec) { s.IPv4, s.IPv6 = netip.Addr{}, netip.Addr{} },
		"private address": func(s *Spec) { s.IPv4 = netip.MustParseAddr("192.168.1.2") },
		"shared address":  func(s *Spec) { s.IPv4 = netip.MustParseAddr("100.64.1.2") },
		"ipv6 as ipv4":    func(s *Spec) { s.IPv4 = netip.MustParseAddr("2001:db8::1") },
		"unique local v6": func(s *Spec) { s.IPv6 = netip.MustParseAddr("fd00::1") },
		"no key":          func(s *Spec) { s.RelayKey = key.RelayPublic{} },
		"no udp port":     func(s *Spec) { s.UDPPort = 0 },
		"unsorted":        func(s *Spec) { s.Networks[0], s.Networks[1] = s.Networks[1], s.Networks[0] },
		"duplicate":       func(s *Spec) { s.Networks[1] = s.Networks[0] },
		"too many":        func(s *Spec) { s.Networks = make([]network.ID, MaxNetworks+1) },
	} {
		spec := validSpec(t)
		mutate(&spec)
		if spec.IsValid() {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestDirectoryLookups(t *testing.T) {
	t.Parallel()
	spec := validSpec(t)
	directory := Directory{Revision: 9, Relays: []Interchange{{RegionID: 1000, Spec: spec}}}
	if granted := directory.ForNetwork(spec.Networks[1]); len(granted) != 1 {
		t.Fatalf("granted %+v", granted)
	}
	if granted := directory.ForNetwork(mustNetwork(t, "01890f00-0000-7000-8000-000000000999")); len(granted) != 0 {
		t.Fatalf("an ungranted Network got %+v", granted)
	}
	if _, found := directory.ByKey(spec.RelayKey); !found {
		t.Fatal("relay not found by key")
	}
}

type fakeStore struct{ changes []Change }

func (store *fakeStore) List(context.Context, accountsession.Session, workspace.ID) (Listing, error) {
	return Listing{}, nil
}

func (store *fakeStore) Change(_ context.Context, change Change) (Result, error) {
	store.changes = append(store.changes, change)
	return Result{}, nil
}

type clock struct{}

func (clock) Now() time.Time { return time.Now() }

type sharedMap struct{ code string }

func (shared sharedMap) Uses(code string, _ key.RelayPublic) bool { return code == shared.code }

func TestServiceRefusesInvalidAndClashingSpecs(t *testing.T) {
	t.Parallel()
	store := &fakeStore{}
	service, err := NewService(store, clock{}, SystemIDs{}, sharedMap{code: "sgp"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := publicid.Parse("01890f00-0000-7000-8000-000000000103")
	if err != nil {
		t.Fatal(err)
	}
	workspaceID := workspace.ID(parsed)
	correlation, err := publicid.Parse("01890f00-0000-7000-8000-000000000999")
	if err != nil {
		t.Fatal(err)
	}
	// An inactive session is refused before anything else.
	if _, err := service.Create(t.Context(), accountsession.Session{}, workspaceID, validSpec(t), correlation); !errors.Is(err, ErrForbidden) {
		t.Fatalf("inactive session: %v", err)
	}
	if _, err := NewService(store, clock{}, SystemIDs{}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a service without the shared map: %v", err)
	}
	clash := validSpec(t)
	clash.RegionCode = "sgp"
	if err := service.checkSpec(clash); !errors.Is(err, ErrConflict) {
		t.Fatalf("a code of the shared map: %v", err)
	}
	if err := service.checkSpec(Spec{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an empty spec: %v", err)
	}
	if len(store.changes) != 0 {
		t.Fatal("a refused change reached the store")
	}
}

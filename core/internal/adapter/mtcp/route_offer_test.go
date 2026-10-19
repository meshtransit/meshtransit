package mtcp

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

type fakeRouteOffers struct {
	mu      sync.Mutex
	offers  [][]netip.Prefix
	keys    []node.Key
	current []netip.Prefix
	err     error
}

func (offers *fakeRouteOffers) ReportRouteOffer(_ context.Context, identity control.AuthenticatedNode,
	prefixes []netip.Prefix) (bool, error) {
	offers.mu.Lock()
	defer offers.mu.Unlock()
	if offers.err != nil {
		return false, offers.err
	}
	offers.offers = append(offers.offers, slices.Clone(prefixes))
	offers.keys = append(offers.keys, identity.NodeKey())
	changed := !slices.Equal(offers.current, prefixes)
	offers.current = slices.Clone(prefixes)
	return changed, nil
}

func (offers *fakeRouteOffers) stored() [][]netip.Prefix {
	offers.mu.Lock()
	defer offers.mu.Unlock()
	return slices.Clone(offers.offers)
}

func hostinfoReport(texts ...string) *mtcpv1.HostinfoReport {
	report := &mtcpv1.HostinfoReport{Hostinfo: &mtcpv1.Hostinfo{Hostname: "router"}}
	for _, text := range texts {
		report.Hostinfo.AdvertisedPrefixes = append(report.Hostinfo.AdvertisedPrefixes,
			sharedmtcp.AppendPrefix(netip.MustParsePrefix(text)))
	}
	return report
}

func TestConversationStoresRouteOffers(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	// Before the session serves a Device the offer waits.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageHostinfoReport,
		hostinfoReport("192.168.1.0/24", "10.20.0.0/16", "0.0.0.0/0", "100.64.0.0/24")); err != nil {
		t.Fatal(err)
	}
	if got := f.routeOffers.stored(); len(got) != 0 {
		t.Fatalf("stored %v before the Device was known", got)
	}
	nodeKey := node.Key(f.session.Hello().GetNodeKey())
	f.talk.authorize(nodeKey, node.DiscoveryKey{}, node.Hostname{}, false)
	waitForRouteOffers(t, f.routeOffers, 1)
	want := []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("192.168.1.0/24")}
	if got := f.routeOffers.stored(); len(got) != 1 || !slices.Equal(got[0], want) {
		t.Fatalf("stored %v, want the usable prefixes sorted", got)
	}
	// The same offer again writes nothing.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageHostinfoReport,
		hostinfoReport("10.20.0.0/16", "192.168.1.0/24")); err != nil {
		t.Fatal(err)
	}
	if got := f.routeOffers.stored(); len(got) != 1 {
		t.Fatalf("an unchanged offer was stored again: %v", got)
	}
	// An empty offer clears it.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageHostinfoReport, hostinfoReport()); err != nil {
		t.Fatal(err)
	}
	if got := f.routeOffers.stored(); len(got) != 2 || len(got[1]) != 0 {
		t.Fatalf("stored %v, want the cleared offer", got)
	}
	// More than the protocol allows is invalid.
	report := hostinfoReport()
	for index := range 257 {
		report.Hostinfo.AdvertisedPrefixes = append(report.Hostinfo.AdvertisedPrefixes, sharedmtcp.AppendPrefix(
			netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index / 256), byte(index % 256), 0}), 24)))
	}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageHostinfoReport, report); err == nil {
		t.Fatal("257 advertised prefixes were accepted")
	}
}

func TestConversationPacesRouteOffers(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	f.talk.nodeKey = node.Key(f.session.Hello().GetNodeKey())
	for index := range routeOfferBurst + 3 {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageHostinfoReport,
			hostinfoReport(netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index), 0, 0}), 16).String())); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.routeOffers.stored(); len(got) != routeOfferBurst {
		t.Fatalf("stored %d offers at once, want the burst of %d", len(got), routeOfferBurst)
	}
	delay, armed := f.routeOfferTimer.pending()
	if !armed || delay != 10*time.Second {
		t.Fatalf("timer %s armed %t, want 10s", delay, armed)
	}
	f.advance(10 * time.Second)
	f.routeOfferTimer.trigger()
	got := f.routeOffers.stored()
	latest := []netip.Prefix{netip.MustParsePrefix("10.6.0.0/16")}
	if len(got) != routeOfferBurst+1 || !slices.Equal(got[len(got)-1], latest) {
		t.Fatalf("stored %v, want the latest offer last", got)
	}
	// The end of the session drops a kept offer.
	for range routeOfferBurst + 1 {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageHostinfoReport, hostinfoReport("10.99.0.0/16")); err != nil {
			t.Fatal(err)
		}
	}
	before := len(f.routeOffers.stored())
	f.talk.stopRouteOfferPacing()
	f.advance(time.Minute)
	f.routeOfferTimer.trigger()
	if after := len(f.routeOffers.stored()); after != before {
		t.Fatalf("stored %d offers after the session ended", after-before)
	}
}

// waitForRouteOffers waits for a store that authorize started in the
// background.
func waitForRouteOffers(t *testing.T, offers *fakeRouteOffers, count int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(offers.stored()) < count {
		if time.Now().After(deadline) {
			t.Fatalf("stored %d offers, want %d", len(offers.stored()), count)
		}
		time.Sleep(time.Millisecond) //nolint:forbidigo // the store runs on its own goroutine
	}
}

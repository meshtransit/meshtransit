package mtcp

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

type fakeExitOffers struct {
	mu      sync.Mutex
	offers  []bool
	current bool
}

func (offers *fakeExitOffers) ReportExitOffer(_ context.Context, _ control.AuthenticatedNode,
	offered bool) (bool, error) {
	offers.mu.Lock()
	defer offers.mu.Unlock()
	offers.offers = append(offers.offers, offered)
	changed := offers.current != offered
	offers.current = offered
	return changed, nil
}

func (offers *fakeExitOffers) stored() []bool {
	offers.mu.Lock()
	defer offers.mu.Unlock()
	return slices.Clone(offers.offers)
}

func waitForExitOffers(t *testing.T, offers *fakeExitOffers, count int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(offers.stored()) < count && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := offers.stored(); len(got) != count {
		t.Fatalf("exit offers stored = %v, want %d", got, count)
	}
}

// An exit offer counts only from a node that listed router.exit.v1 (one that
// did not withdraws any offer), is stored once per change, and waits for the session's Device like a route
// offer.
func TestConversationStoresExitOffers(t *testing.T) {
	t.Parallel()
	for _, capable := range []bool{false, true} {
		f := newConversationFixture(t, sharedmtcp.MessagePing)
		exits := &fakeExitOffers{}
		f.talk.application.options.ExitOffers = exits
		if capable {
			f.session.capabilities = append(f.session.capabilities, "router.exit.v1")
		}
		report := hostinfoReport("10.20.0.0/16")
		report.Hostinfo.ExitOffered = true
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageHostinfoReport, report); err != nil {
			t.Fatal(err)
		}
		if got := exits.stored(); len(got) != 0 {
			t.Fatalf("stored %v before the Device was known", got)
		}
		f.talk.authorize(node.Key(f.session.Hello().GetNodeKey()), node.DiscoveryKey{}, node.Hostname{}, false)
		waitForRouteOffers(t, f.routeOffers, 1)
		if !capable {
			// It cannot serve: whatever it says, it withdraws an offer.
			waitForExitOffers(t, exits, 1)
			if got := exits.stored(); got[0] {
				t.Fatalf("a node without router.exit.v1 stored the offer %v", got)
			}
			continue
		}
		waitForExitOffers(t, exits, 1)
		if got := exits.stored(); !got[0] {
			t.Fatalf("stored %v, want the offer", got)
		}
		// The same offer again writes nothing; withdrawing it is stored.
		f.advance(time.Minute)
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageHostinfoReport, report); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
		if got := exits.stored(); len(got) != 1 {
			t.Fatalf("an unchanged exit offer was stored again: %v", got)
		}
		f.advance(time.Minute)
		report.Hostinfo.ExitOffered = false
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageHostinfoReport, report); err != nil {
			t.Fatal(err)
		}
		waitForExitOffers(t, exits, 2)
		if got := exits.stored(); got[1] {
			t.Fatalf("stored %v, want the withdrawn offer", got)
		}
		if got := f.routeOffers.stored(); len(got) != 1 {
			t.Fatalf("unchanged subnets were stored again with the exit offer: %v", got)
		}
	}
}

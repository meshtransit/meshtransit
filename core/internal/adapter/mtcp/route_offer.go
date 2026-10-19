package mtcp

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/site"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// RouteOffers stores the subnets a Device's own configuration offers to
// forward (mtcp-v1 §8.2) and reports whether they changed.
type RouteOffers interface {
	ReportRouteOffer(ctx context.Context, identity control.AuthenticatedNode, prefixes []netip.Prefix) (bool, error)
}

const (
	// A stored offer is a database write that may move the Network's maps
	// when the Device is a router; nodes send one per session and on
	// change.
	routeOfferBurst = 4
	routeOfferRate  = 0.1
	// routeOfferTimeout bounds one store.
	routeOfferTimeout = 5 * time.Second
)

// routeOfferPacing stores a session's offers at most at the budget's rate.
// An offer over it is kept, replacing any kept before, and stored when the
// budget allows, so the latest one is never lost; one waiting for the
// session's Device is stored once the Device is authorized. One store runs
// at a time (busy); mu is never held across it. stored is the offer last
// stored for the session's current Device, and known the node key it was
// stored with; authorize forgets them (epoch), since a new registration may
// be another Device.
type routeOfferPacing struct {
	mu      sync.Mutex
	running sync.WaitGroup
	stopped bool
	busy    bool
	budget  rateBudget
	waiting []netip.Prefix
	pending bool
	timer   endpointTimer
	stored  []netip.Prefix
	known   node.Key // the node key stored was stored with; zero for none
	epoch   uint64   // advances when authorize forgets stored
}

// hostinfo reads the offer of a HostinfoReport; the other fields are not
// used yet.
func (conversation *conversation) hostinfo(report *mtcpv1.HostinfoReport) error {
	offered := report.GetHostinfo().GetAdvertisedPrefixes()
	if len(offered) > site.MaximumOfferedPrefixes {
		return Violation(mtcpv1.Error_INVALID, "too many advertised prefixes")
	}
	if conversation.application.options.RouteOffers == nil {
		return nil
	}
	parsed := make([]netip.Prefix, 0, len(offered))
	malformed := 0
	for _, value := range offered {
		prefix, err := sharedmtcp.ParsePrefix(value)
		if err != nil {
			malformed++
			continue
		}
		parsed = append(parsed, prefix)
	}
	kept, dropped := site.ParseOffer(parsed)
	conversation.application.options.Metrics.routeOfferPrefixesDropped(malformed + dropped)
	conversation.reportRouteOffer(kept)
	return nil
}

// reportRouteOffer stores prefixes now, or keeps them until the budget and
// the session's Device allow.
func (conversation *conversation) reportRouteOffer(prefixes []netip.Prefix) {
	pacing := &conversation.routeOfferPacing
	pacing.mu.Lock()
	if pacing.stopped {
		pacing.mu.Unlock()
		return
	}
	pacing.waiting, pacing.pending = prefixes, true
	next, ok, refused := conversation.claimRouteOfferLocked()
	pacing.mu.Unlock()
	if refused {
		conversation.application.options.Metrics.limited(limitRouteOffer)
	}
	if ok {
		conversation.storeRouteOffers(next)
	}
}

// flushRouteOffer stores a kept offer once the budget allows, or once the
// session's Device is authorized.
func (conversation *conversation) flushRouteOffer() {
	pacing := &conversation.routeOfferPacing
	pacing.mu.Lock()
	next, ok, _ := conversation.claimRouteOfferLocked()
	pacing.mu.Unlock()
	if ok {
		conversation.storeRouteOffers(next)
	}
}

// claimRouteOfferLocked takes the kept offer if it may be stored now, or
// arms the timer for when the budget allows; refused reports the budget
// held it back. Without an authorized Device the offer waits for authorize.
func (conversation *conversation) claimRouteOfferLocked() (kept []netip.Prefix, ok, refused bool) {
	pacing := &conversation.routeOfferPacing
	if pacing.stopped || pacing.busy || !pacing.pending || !conversation.currentKey().IsValid() {
		return nil, false, false
	}
	if wait, admitted := pacing.budget.spend(conversation.application.now(), 1); !admitted {
		delay := max(wait, time.Millisecond)
		if pacing.timer == nil {
			pacing.timer = conversation.application.routeOfferTimer(delay, conversation.flushRouteOffer)
		} else {
			pacing.timer.Reset(delay)
		}
		return nil, false, true
	}
	kept = pacing.waiting
	pacing.waiting, pacing.pending, pacing.busy = nil, false, true
	pacing.running.Add(1)
	return kept, true, false
}

// storeRouteOffers stores claimed offers until none may be stored now.
func (conversation *conversation) storeRouteOffers(prefixes []netip.Prefix) {
	pacing := &conversation.routeOfferPacing
	for {
		conversation.storeRouteOffer(prefixes)
		pacing.mu.Lock()
		pacing.busy = false
		pacing.running.Done()
		next, ok, _ := conversation.claimRouteOfferLocked()
		pacing.mu.Unlock()
		if !ok {
			return
		}
		prefixes = next
	}
}

// storeRouteOffer stores one offer unless this session already stored the
// same one. A failed store is logged and retried with the node's next
// report; the node reports again on every change and every session.
func (conversation *conversation) storeRouteOffer(prefixes []netip.Prefix) {
	pacing := &conversation.routeOfferPacing
	metrics := conversation.application.options.Metrics
	nodeKey := conversation.currentKey()
	pacing.mu.Lock()
	epoch := pacing.epoch
	same := pacing.known.IsValid() && pacing.known == nodeKey && slices.Equal(pacing.stored, prefixes)
	pacing.mu.Unlock()
	if same {
		metrics.routeOffer(routeOfferUnchanged)
		return
	}
	machine, err := control.NewAuthenticatedMachine(node.MachineKey(conversation.session.Machine()))
	if err != nil {
		metrics.routeOffer(routeOfferFailed)
		return
	}
	identity, err := machine.BindNodeKey(nodeKey)
	if err != nil {
		metrics.routeOffer(routeOfferFailed)
		return
	}
	ctx, cancel := context.WithTimeout(conversation.session.ctx, routeOfferTimeout)
	defer cancel()
	changed, err := conversation.application.options.RouteOffers.ReportRouteOffer(ctx, identity, prefixes)
	if err != nil {
		metrics.routeOffer(routeOfferFailed)
		if !errors.Is(err, context.Canceled) {
			conversation.application.options.Logger.WarnContext(ctx, "mtcp route offer not stored", "error", err)
		}
		return
	}
	pacing.mu.Lock()
	if pacing.epoch == epoch {
		pacing.stored, pacing.known = slices.Clone(prefixes), nodeKey
	}
	pacing.mu.Unlock()
	if changed {
		metrics.routeOffer(routeOfferChanged)
	} else {
		metrics.routeOffer(routeOfferUnchanged)
	}
}

// forgetRouteOffer drops what this session stored: after a registration or
// rotation the session may serve another Device, whose offer it has not
// stored yet.
func (conversation *conversation) forgetRouteOffer() {
	pacing := &conversation.routeOfferPacing
	pacing.mu.Lock()
	pacing.stored, pacing.known = nil, node.Key{}
	pacing.epoch++
	pacing.mu.Unlock()
}

// stopRouteOfferPacing ends the pacing when the session ends, dropping a
// kept offer, and waits for a store already running; its timeout bounds
// that wait.
func (conversation *conversation) stopRouteOfferPacing() {
	pacing := &conversation.routeOfferPacing
	pacing.mu.Lock()
	pacing.stopped, pacing.waiting, pacing.pending = true, nil, false
	if pacing.timer != nil {
		pacing.timer.Stop()
	}
	pacing.mu.Unlock()
	pacing.running.Wait()
}

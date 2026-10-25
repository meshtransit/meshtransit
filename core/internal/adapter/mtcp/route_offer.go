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

// ExitOffers stores whether a Device's own configuration offers to be an
// exit node (mtcp-v1 §8.2, exit_offered) and reports whether it changed.
type ExitOffers interface {
	ReportExitOffer(ctx context.Context, identity control.AuthenticatedNode, offered bool) (bool, error)
}

// deviceOffer is what a HostinfoReport offers: subnets to forward and, from
// a node that can be an exit node (exitKnown), whether it offers to be one.
type deviceOffer struct {
	prefixes  []netip.Prefix
	exit      bool
	exitKnown bool
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
	waiting deviceOffer
	pending bool
	timer   endpointTimer
	stored  []netip.Prefix
	// routesStored says stored holds a stored offer, not merely none yet.
	routesStored bool
	// storedExit is the exit offer last stored, valid when exitStored.
	storedExit bool
	exitStored bool
	known      node.Key // the node key stored was stored with; zero for none
	epoch      uint64   // advances when authorize forgets stored
}

// hostinfo reads the offers of a HostinfoReport; the other fields are not
// used yet. exit_offered counts only from a node that listed router.exit.v1:
// with an exit offer store, one that does not withdraws any offer it made
// before, since it could not serve.
func (conversation *conversation) hostinfo(report *mtcpv1.HostinfoReport) error {
	offered := report.GetHostinfo().GetAdvertisedPrefixes()
	if len(offered) > site.MaximumOfferedPrefixes {
		return Violation(mtcpv1.Error_INVALID, "too many advertised prefixes")
	}
	options := conversation.application.options
	exitKnown := options.ExitOffers != nil
	if options.RouteOffers == nil && !exitKnown {
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
	conversation.reportRouteOffer(deviceOffer{prefixes: kept,
		exit:      exitKnown && conversation.session.Supports("router.exit.v1") && report.GetHostinfo().GetExitOffered(),
		exitKnown: exitKnown})
	return nil
}

// reportRouteOffer stores prefixes now, or keeps them until the budget and
// the session's Device allow.
func (conversation *conversation) reportRouteOffer(offer deviceOffer) {
	pacing := &conversation.routeOfferPacing
	pacing.mu.Lock()
	if pacing.stopped {
		pacing.mu.Unlock()
		return
	}
	pacing.waiting, pacing.pending = offer, true
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
func (conversation *conversation) claimRouteOfferLocked() (kept deviceOffer, ok, refused bool) {
	pacing := &conversation.routeOfferPacing
	if pacing.stopped || pacing.busy || !pacing.pending || !conversation.currentKey().IsValid() {
		return deviceOffer{}, false, false
	}
	if wait, admitted := pacing.budget.spend(conversation.application.now(), 1); !admitted {
		delay := max(wait, time.Millisecond)
		if pacing.timer == nil {
			pacing.timer = conversation.application.routeOfferTimer(delay, conversation.flushRouteOffer)
		} else {
			pacing.timer.Reset(delay)
		}
		return deviceOffer{}, false, true
	}
	kept = pacing.waiting
	pacing.waiting, pacing.pending, pacing.busy = deviceOffer{}, false, true
	pacing.running.Add(1)
	return kept, true, false
}

// storeRouteOffers stores claimed offers until none may be stored now.
func (conversation *conversation) storeRouteOffers(offer deviceOffer) {
	pacing := &conversation.routeOfferPacing
	for {
		conversation.storeRouteOffer(offer)
		pacing.mu.Lock()
		pacing.busy = false
		pacing.running.Done()
		next, ok, _ := conversation.claimRouteOfferLocked()
		pacing.mu.Unlock()
		if !ok {
			return
		}
		offer = next
	}
}

// storeRouteOffer stores one offer's subnets and exit offer, each unless
// this session already stored the same. A failed store is logged and
// retried with the node's next report; the node reports again on every
// change and every session.
func (conversation *conversation) storeRouteOffer(offer deviceOffer) {
	pacing := &conversation.routeOfferPacing
	options := conversation.application.options
	nodeKey := conversation.currentKey()
	pacing.mu.Lock()
	epoch := pacing.epoch
	current := pacing.known.IsValid() && pacing.known == nodeKey
	sameRoutes := current && pacing.routesStored && slices.Equal(pacing.stored, offer.prefixes)
	sameExit := current && pacing.exitStored && pacing.storedExit == offer.exit
	pacing.mu.Unlock()
	storeRoutes := options.RouteOffers != nil && !sameRoutes
	storeExit := offer.exitKnown && options.ExitOffers != nil && !sameExit
	if options.RouteOffers != nil && sameRoutes {
		options.Metrics.routeOffer(routeOfferUnchanged)
	}
	if offer.exitKnown && options.ExitOffers != nil && sameExit {
		options.Metrics.exitOffer(routeOfferUnchanged)
	}
	if !storeRoutes && !storeExit {
		return
	}
	identity, err := conversation.offerIdentity(nodeKey)
	if err != nil {
		if storeRoutes {
			options.Metrics.routeOffer(routeOfferFailed)
		}
		if storeExit {
			options.Metrics.exitOffer(routeOfferFailed)
		}
		return
	}
	ctx, cancel := context.WithTimeout(conversation.session.ctx, routeOfferTimeout)
	defer cancel()
	if storeRoutes {
		changed, err := options.RouteOffers.ReportRouteOffer(ctx, identity, offer.prefixes)
		options.Metrics.routeOffer(offerResult(changed, err))
		if err != nil && !errors.Is(err, context.Canceled) {
			options.Logger.WarnContext(ctx, "mtcp route offer not stored", "error", err)
		}
		if err == nil {
			pacing.mu.Lock()
			if pacing.epoch == epoch {
				pacing.stored, pacing.routesStored, pacing.known = slices.Clone(offer.prefixes), true, nodeKey
			}
			pacing.mu.Unlock()
		}
	}
	if storeExit {
		changed, err := options.ExitOffers.ReportExitOffer(ctx, identity, offer.exit)
		options.Metrics.exitOffer(offerResult(changed, err))
		if err != nil && !errors.Is(err, context.Canceled) {
			options.Logger.WarnContext(ctx, "mtcp exit offer not stored", "error", err)
		}
		if err == nil {
			pacing.mu.Lock()
			if pacing.epoch == epoch && (pacing.known == nodeKey || !pacing.known.IsValid()) {
				pacing.storedExit, pacing.exitStored, pacing.known = offer.exit, true, nodeKey
			}
			pacing.mu.Unlock()
		}
	}
}

// offerIdentity is the session's Device as it stores its offers.
func (conversation *conversation) offerIdentity(nodeKey node.Key) (control.AuthenticatedNode, error) {
	machine, err := conversation.authenticatedMachine()
	if err != nil {
		return control.AuthenticatedNode{}, err
	}
	return machine.BindNodeKey(nodeKey)
}

// offerResult is the metric result of one store.
func offerResult(changed bool, err error) string {
	switch {
	case err != nil:
		return routeOfferFailed
	case changed:
		return routeOfferChanged
	default:
		return routeOfferUnchanged
	}
}

// forgetRouteOffer drops what this session stored: after a registration or
// rotation the session may serve another Device, whose offer it has not
// stored yet.
func (conversation *conversation) forgetRouteOffer() {
	pacing := &conversation.routeOfferPacing
	pacing.mu.Lock()
	pacing.stored, pacing.routesStored, pacing.known = nil, false, node.Key{}
	pacing.storedExit, pacing.exitStored = false, false
	pacing.epoch++
	pacing.mu.Unlock()
}

// stopRouteOfferPacing ends the pacing when the session ends, dropping a
// kept offer, and waits for a store already running; its timeout bounds
// that wait.
func (conversation *conversation) stopRouteOfferPacing() {
	pacing := &conversation.routeOfferPacing
	pacing.mu.Lock()
	pacing.stopped, pacing.waiting, pacing.pending = true, deviceOffer{}, false
	if pacing.timer != nil {
		pacing.timer.Stop()
	}
	pacing.mu.Unlock()
	pacing.running.Wait()
}

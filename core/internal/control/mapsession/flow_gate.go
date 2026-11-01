package mapsession

import (
	"context"
	"errors"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// The ticket gate (connection logs design §16e, C71): Core signs tickets
// only while a receiver that accepts them reported in the last 10 minutes.
const (
	// FlowGateAge is how long one read of the gate answers a replica's
	// streams; a failed read answers closed for as long.
	FlowGateAge = 30 * time.Second
	// flowGateTimeout bounds one read of the gate.
	flowGateTimeout = 5 * time.Second
	// flowGateSpread spreads the first tickets after the gate opens, so a
	// replica's streams do not all sign at once.
	flowGateSpread = time.Minute
)

// ErrInvalidFlowGate reports a gate built without its reader or clock.
var ErrInvalidFlowGate = errors.New("map session: invalid connection log ticket gate")

// FlowGateReader reads the receivers that can take this Core's tickets.
type FlowGateReader interface {
	ReadFlowGate(ctx context.Context) (connectionlog.ReceiverGate, error)
}

// FlowReceiverGate tells a stream whether tickets may be signed. Withheld
// counts a ticket the gate held back.
type FlowReceiverGate interface {
	FlowGate(ctx context.Context) FlowGateState
	Withheld()
}

// FlowGateState is one answer of the gate: open or not, when this replica
// last saw it open after it was closed, and when it is read again.
type FlowGateState struct {
	Open     bool
	OpenedAt time.Time
	Until    time.Time
}

// FlowGateCache is the replica's FlowReceiverGate: one read every
// FlowGateAge, by whichever stream asks first; the others answer the last
// state meanwhile and never wait on the database.
type FlowGateCache struct {
	reader FlowGateReader
	now    func() time.Time

	mu      sync.Mutex
	state   FlowGateState
	read    bool
	reading bool
	readAt  time.Time
	last    connectionlog.ReceiverGate
	lastErr error

	withheld atomic.Uint64
}

// NewFlowGateCache builds a closed gate that reads reader when first asked.
func NewFlowGateCache(reader FlowGateReader, now func() time.Time) (*FlowGateCache, error) {
	if isNilDependency(reader) || now == nil {
		return nil, ErrInvalidFlowGate
	}
	return &FlowGateCache{reader: reader, now: now}, nil
}

// FlowGate answers the gate, reading it when the last read aged.
func (cache *FlowGateCache) FlowGate(ctx context.Context) FlowGateState {
	cache.mu.Lock()
	if cache.reading || (cache.read && cache.now().Sub(cache.readAt) < FlowGateAge) {
		state := cache.state
		cache.mu.Unlock()
		return state
	}
	cache.reading = true
	cache.mu.Unlock()
	gate, err := cache.readGate(ctx)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := cache.now()
	open := err == nil && gate.Accepting > 0
	if open && !cache.state.Open {
		cache.state.OpenedAt = now
	}
	cache.state.Open, cache.state.Until = open, now.Add(FlowGateAge)
	cache.read, cache.reading, cache.readAt, cache.last, cache.lastErr = true, false, now, gate, err
	return cache.state
}

// readGate reads the gate for the replica, not the stream: a stream that
// ends does not fail it for the others. A reader that panics leaves the
// gate closed and readable again (review s4c3 L11).
func (cache *FlowGateCache) readGate(ctx context.Context) (gate connectionlog.ReceiverGate, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			gate, err = connectionlog.ReceiverGate{}, errFlowGateReadPanicked
		}
	}()
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), flowGateTimeout)
	defer cancel()
	return cache.reader.ReadFlowGate(readCtx)
}

var errFlowGateReadPanicked = errors.New("map session: the ticket gate read panicked")

// Withheld counts a ticket the gate held back.
func (cache *FlowGateCache) Withheld() { cache.withheld.Add(1) }

// FlowGateSnapshot is what the gate last read, for metrics.
type FlowGateSnapshot struct {
	Read     bool
	Open     bool
	Failed   bool
	ReadAt   time.Time
	Gate     connectionlog.ReceiverGate
	Withheld uint64
}

// Snapshot returns what the gate last read.
func (cache *FlowGateCache) Snapshot() FlowGateSnapshot {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	return FlowGateSnapshot{
		Read: cache.read, Open: cache.state.Open, Failed: cache.lastErr != nil, ReadAt: cache.readAt, Gate: cache.last,
		Withheld: cache.withheld.Load(),
	}
}

// flowGateDelay is a Device's place in the spread after the gate opens.
func flowGateDelay(device node.ID) time.Duration {
	hash := fnv.New64a()
	id := publicid.ID(device).Bytes()
	_, _ = hash.Write(id[:])
	return time.Duration(hash.Sum64() % uint64(flowGateSpread))
}

// gateFlowTicket applies the gate to a ticket the settings would send
// (C71). It reports whether the stream must stop here: a closed gate keeps
// the ticket the node holds while its grant stands, withdraws it when the
// grant changed or the node's authority now ends first, and signs nothing
// new; an open gate holds every signing back until the Device's place in
// the spread after it opened, renewals of tickets kept while it was closed
// included (review s4c3 H1). A stream counts once as withheld per closed
// spell.
func (service *StreamService) gateFlowTicket(ctx context.Context, sink FlowTicketSink, current Snapshot,
	state *flowTicketState, grant FlowGrant, now time.Time,
) (bool, error) {
	gate := service.options.FlowGate
	if isNilDependency(gate) {
		return false, nil
	}
	answer := gate.FlowGate(ctx)
	if !answer.Open {
		state.gateUntil = answer.Until
		if state.gateUntil.IsZero() || !state.gateUntil.After(now) {
			state.gateUntil = now.Add(flowLogFailureAge)
		}
		if !state.withheld {
			state.withheld = true
			gate.Withheld()
		}
		keep := state.sent && state.grant.Equal(grant) &&
			!now.Add(current.untilDeadline(current.KeyExpiry())).Before(state.expires)
		if keep || !state.sent {
			return true, nil
		}
		if _, err := sink.SendFlowTicket(ctx, state.grant, false); err != nil && !errors.Is(err, ErrNoFlowTickets) {
			return true, errors.Join(ErrStreamWrite, err)
		}
		state.sent = false
		return true, nil
	}
	state.withheld = false
	if hold := answer.OpenedAt.Add(flowGateDelay(grant.Device)); now.Before(hold) {
		state.holdUntil = hold
		return true, nil
	}
	return false, nil
}

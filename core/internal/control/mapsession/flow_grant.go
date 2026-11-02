package mapsession

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// Connection log tickets (connection logs design §16b C25–C27, mtcp-v1
// §9.1): a node whose Network logs, in a Workspace that has the feature, gets
// a FlowTicket over its map stream, renewed at half its life; one that loses
// it gets an empty ticket.

// MaximumFlowGrantIDs bounds the Site and Exit Pool IDs of one grant, as the
// token does (flowlog-v1 §3).
const MaximumFlowGrantIDs = 64

// FlowLogSettingsAge bounds how long a Network's settings read for one
// revision are reused: a revoked feature advances no revision (C31), so it
// reaches tickets within this age.
const FlowLogSettingsAge = time.Minute

// flowLogFailureAge is how long a failed read answers before another is
// tried: a database slowdown costs one read per Network this often.
const flowLogFailureAge = 5 * time.Second

// ErrInvalidFlowGrant reports malformed settings or a malformed grant.
var ErrInvalidFlowGrant = errors.New("map session: invalid connection log grant")

// ErrNoFlowTickets is what a FlowTicketSink answers when its session takes
// no tickets (it lacks flow.report1, or Core signs none): the stream stops
// asking.
var ErrNoFlowTickets = errors.New("map session: the session takes no connection log tickets")

// FlowLogSettings is a Network's connection log setting as tickets need it.
// Enabled holds only when the Network logs and its Workspace has the
// feature.
type FlowLogSettings struct {
	Enabled       bool
	Forwarded     bool
	WindowSeconds int
	// Provider is the destination's type (schema 273): the gate signs
	// only while every receiver writes to it. Empty: no credential.
	Provider string
}

// FlowLogReader reads a Network's settings.
type FlowLogReader interface {
	ReadFlowLog(context.Context, network.Scope) (FlowLogSettings, error)
}

// FlowRole is what a node logs as (flowlog-v1 §3).
type FlowRole uint8

// Roles in token order.
const (
	FlowRoleDevice FlowRole = iota + 1
	FlowRoleRouter
	FlowRoleExit
)

// FlowGrant is what one FlowTicket's token names. Sites and ExitPools come
// only with forwarded logging, sorted, at most MaximumFlowGrantIDs in all.
type FlowGrant struct {
	Scope         network.Scope
	Device        node.ID
	MachineKey    node.MachineKey
	Roles         []FlowRole
	Sites         []publicid.ID
	ExitPools     []publicid.ID
	WindowSeconds int
	// NotAfter is the node's authority deadline on the database's clock,
	// and Deadline the same instant on this host's: a signer bounds the
	// token by Deadline. Equal compares NotAfter only.
	NotAfter time.Time
	Deadline time.Time
}

// Equal reports whether two grants name the same token content.
func (grant FlowGrant) Equal(other FlowGrant) bool {
	return grant.Scope == other.Scope && grant.Device == other.Device && grant.MachineKey == other.MachineKey &&
		slices.Equal(grant.Roles, other.Roles) && slices.Equal(grant.Sites, other.Sites) &&
		slices.Equal(grant.ExitPools, other.ExitPools) && grant.WindowSeconds == other.WindowSeconds &&
		grant.NotAfter.Equal(other.NotAfter)
}

// FlowGrant derives the node's grant under settings; false when the node
// must not log.
func (snapshot Snapshot) FlowGrant(settings FlowLogSettings) (FlowGrant, bool) {
	if !snapshot.IsValid() || !settings.Enabled || !snapshot.MachineKey().IsValid() {
		return FlowGrant{}, false
	}
	grant := FlowGrant{
		Scope: snapshot.Scope(), Device: snapshot.NodeID(), MachineKey: snapshot.MachineKey(),
		Roles: []FlowRole{FlowRoleDevice}, WindowSeconds: settings.WindowSeconds, NotAfter: snapshot.KeyExpiry(),
		Deadline: time.Now().Add(snapshot.untilDeadline(snapshot.KeyExpiry())),
	}
	if !settings.Forwarded {
		return grant, true
	}
	// Forwarded traffic is counted only for what the node serves (s2c). An
	// exit node serves one pool, so pools go first; a router with more than
	// the room left has the Sites past it unnamed.
	routes := snapshot.Routes()
	refs := make([]string, 0, len(routes.ServedExits()))
	for _, exit := range routes.ServedExits() {
		refs = append(refs, exit.Ref)
	}
	var room int
	grant.ExitPools, room = flowGrantIDs(refs, MaximumFlowGrantIDs)
	refs = refs[:0]
	for _, site := range routes.Served() {
		refs = append(refs, site.Ref)
	}
	grant.Sites, _ = flowGrantIDs(refs, room)
	if len(grant.Sites) != 0 {
		grant.Roles = append(grant.Roles, FlowRoleRouter)
	}
	if len(grant.ExitPools) != 0 {
		grant.Roles = append(grant.Roles, FlowRoleExit)
	}
	return grant, true
}

// flowGrantIDs parses refs into sorted unique IDs, at most room of them;
// a ref that is not a public ID is left out.
func flowGrantIDs(refs []string, room int) ([]publicid.ID, int) {
	ids := make([]publicid.ID, 0, len(refs))
	for _, ref := range refs {
		if id, err := publicid.Parse(ref); err == nil {
			ids = append(ids, id)
		}
	}
	slices.SortFunc(ids, func(a, b publicid.ID) int {
		left, right := a.Bytes(), b.Bytes()
		return bytes.Compare(left[:], right[:])
	})
	ids = slices.Compact(ids)
	if len(ids) > room {
		ids = ids[:room]
	}
	if len(ids) == 0 {
		return nil, room
	}
	return ids, room - len(ids)
}

// FlowTicketSink is a sink that sends FlowTickets. TakesFlowTickets reports
// whether its session takes any (it negotiated flow.report1 on a Core that
// signs); the stream reads no settings otherwise. SendFlowTicket signs and
// sends a ticket for grant and returns its token's expiry on this host's
// clock; with on false it sends the empty ticket that turns logging off.
// ErrNoFlowTickets means the session takes none; a zero expiry with no
// error, that none was sent this time.
type FlowTicketSink interface {
	TakesFlowTickets() bool
	SendFlowTicket(ctx context.Context, grant FlowGrant, on bool) (time.Time, error)
}

// flowTicketState is what one stream last read and sent.
type flowTicketState struct {
	refused bool // the sink takes no tickets: the stream stops asking
	// read holds the settings last read, for readRevision at readAt; a
	// failed read only sets failedAt.
	read         bool
	settings     FlowLogSettings
	readRevision int64
	readAt       time.Time
	failedAt     time.Time
	// sent holds a ticket with a token that went out and was not
	// withdrawn, its grant and its token's expiry.
	sent    bool
	grant   FlowGrant
	expires time.Time
	renewAt time.Time
	// gateUntil is when a closed ticket gate is asked again; holdUntil
	// when a first ticket held back by the spread after it opened goes.
	gateUntil time.Time
	holdUntil time.Time
	withheld  bool
}

// readDue reports whether the settings must be read again for current.
func (state flowTicketState) readDue(current Snapshot, now time.Time) bool {
	if !state.failedAt.IsZero() && now.Sub(state.failedAt) < flowLogFailureAge {
		return false
	}
	return !state.read || current.NetworkRevision() != state.readRevision ||
		now.Sub(state.readAt) >= FlowLogSettingsAge || (state.sent && !now.Before(state.renewAt))
}

// nextDue is when the stream must look again: a renewal, the settings'
// age or a failed read's retry.
func (state flowTicketState) nextDue() time.Time {
	if state.refused {
		return time.Time{}
	}
	var due time.Time
	consider := func(at time.Time) {
		if !at.IsZero() && (due.IsZero() || at.Before(due)) {
			due = at
		}
	}
	if state.read {
		consider(state.readAt.Add(FlowLogSettingsAge))
	}
	if !state.failedAt.IsZero() {
		consider(state.failedAt.Add(flowLogFailureAge))
	}
	if state.sent {
		consider(state.renewAt)
	}
	consider(state.gateUntil)
	consider(state.holdUntil)
	return due
}

// syncFlowTicket sends what moves the node from state to current: a new
// ticket when the grant changed or its token passed half its life, an empty
// one when logging ended or the node's authority now ends before the token
// it holds. Settings are read only when the revision moved, they aged or a
// renewal is due; a failed read changes nothing (the token lapses on its
// own). Only a sink write ends the stream.
func (service *StreamService) syncFlowTicket(ctx context.Context, sink FlowTicketSink, current Snapshot,
	state *flowTicketState,
) error {
	reader := service.options.FlowLogs
	if isNilDependency(reader) || state.refused || !current.IsValid() {
		return nil
	}
	if !sink.TakesFlowTickets() {
		// A session that stopped taking tickets (it joined a cluster) gives
		// back the token it holds.
		if state.sent {
			if _, err := sink.SendFlowTicket(ctx, state.grant, false); err != nil &&
				!errors.Is(err, ErrNoFlowTickets) {
				return errors.Join(ErrStreamWrite, err)
			}
		}
		*state = flowTicketState{refused: true}
		return nil
	}
	now := time.Now()
	// The gate's wake-ups hold only for this pass: a stale one would hide
	// the next (review s4c3 M3).
	state.gateUntil, state.holdUntil = time.Time{}, time.Time{}
	if state.readDue(current, now) {
		operationCtx, cancel := context.WithTimeout(ctx, service.options.SnapshotTimeout)
		settings, err := readFlowLog(operationCtx, reader, current)
		cancel()
		if err != nil {
			state.failedAt = now
			return nil
		}
		state.read, state.settings, state.readRevision, state.readAt, state.failedAt =
			true, settings, current.NetworkRevision(), now, time.Time{}
	}
	// Only settings read for this revision within their age sign anything
	// (review s4b H1): after a failed read the node keeps what it holds,
	// unless its authority now ends before that token does.
	if !state.read || !state.failedAt.IsZero() || state.readRevision != current.NetworkRevision() ||
		now.Sub(state.readAt) >= FlowLogSettingsAge {
		if state.sent && time.Now().Add(current.untilDeadline(current.KeyExpiry())).Before(state.expires) {
			if _, err := sink.SendFlowTicket(ctx, state.grant, false); err != nil && !errors.Is(err, ErrNoFlowTickets) {
				return errors.Join(ErrStreamWrite, err)
			}
			state.sent = false
		}
		return nil
	}
	grant, on := current.FlowGrant(state.settings)
	if on {
		if stop, err := service.gateFlowTicket(ctx, sink, current, state, grant, now); stop || err != nil {
			return err
		}
	}
	switch {
	case !on && !state.sent:
		return nil
	case on && state.sent && state.grant.Equal(grant) && now.Before(state.renewAt):
		return nil
	}
	expires, err := sink.SendFlowTicket(ctx, grant, on)
	switch {
	case errors.Is(err, ErrNoFlowTickets):
		state.refused, state.sent = true, false
		return nil
	case err != nil:
		return errors.Join(ErrStreamWrite, err)
	case !on:
		state.sent = false
		return nil
	case !expires.IsZero():
		state.sent, state.grant, state.expires, state.renewAt = true, grant, expires, now.Add(expires.Sub(now)/2)
		return nil
	case state.sent && grant.Deadline.Before(state.expires):
		// No token could be signed, and the one the node holds outlives its
		// authority: take it back.
		if _, err := sink.SendFlowTicket(ctx, grant, false); err != nil && !errors.Is(err, ErrNoFlowTickets) {
			return errors.Join(ErrStreamWrite, err)
		}
		state.sent = false
	}
	return nil
}

// RevisionFlowLogReader is a FlowLogReader that may serve the settings it
// read for the snapshot's Network revision.
type RevisionFlowLogReader interface {
	ReadFlowLogAt(context.Context, network.Scope, int64) (FlowLogSettings, error)
}

func readFlowLog(ctx context.Context, reader FlowLogReader, current Snapshot) (FlowLogSettings, error) {
	if cached, ok := reader.(RevisionFlowLogReader); ok {
		return cached.ReadFlowLogAt(ctx, current.Scope(), current.NetworkRevision())
	}
	return reader.ReadFlowLog(ctx, current.Scope())
}

// FlowLogCache shares one read of a Network's settings among the streams
// of a replica for one revision, for at most FlowLogSettingsAge; one read
// at a time per Network, and a failed one answers for flowLogFailureAge.
type FlowLogCache struct {
	reader FlowLogReader
	now    func() time.Time
	limit  int

	mu      sync.Mutex
	entries map[network.ID]*flowLogEntry
}

type flowLogEntry struct {
	revision int64
	readAt   time.Time
	settings FlowLogSettings
	err      error
	// reading is closed when a read in flight ends.
	reading chan struct{}
}

// NewFlowLogCache caches reader's answers for at most limit Networks.
func NewFlowLogCache(reader FlowLogReader, limit int, now func() time.Time) (*FlowLogCache, error) {
	if isNilDependency(reader) || limit < 1 || now == nil {
		return nil, ErrInvalidFlowGrant
	}
	return &FlowLogCache{reader: reader, now: now, limit: limit, entries: make(map[network.ID]*flowLogEntry)}, nil
}

// ReadFlowLog reads without a revision: never from the cache.
func (cache *FlowLogCache) ReadFlowLog(ctx context.Context, scope network.Scope) (FlowLogSettings, error) {
	return cache.reader.ReadFlowLog(ctx, scope)
}

// ReadFlowLogAt serves the settings read at revision or later, while fresh,
// or the failure of a read that just failed.
func (cache *FlowLogCache) ReadFlowLogAt(ctx context.Context, scope network.Scope, revision int64,
) (FlowLogSettings, error) {
	id := scope.NetworkID()
	for {
		cache.mu.Lock()
		entry := cache.entries[id]
		if entry != nil && entry.reading != nil {
			wait := entry.reading
			cache.mu.Unlock()
			select {
			case <-ctx.Done():
				return FlowLogSettings{}, ctx.Err()
			case <-wait:
				continue
			}
		}
		now := cache.now()
		if entry != nil && entry.err != nil && now.Sub(entry.readAt) < flowLogFailureAge {
			err := entry.err
			cache.mu.Unlock()
			return FlowLogSettings{}, err
		}
		if entry != nil && entry.err == nil && entry.revision >= revision && now.Sub(entry.readAt) < FlowLogSettingsAge {
			settings := entry.settings
			cache.mu.Unlock()
			return settings, nil
		}
		if entry == nil && len(cache.entries) >= cache.limit {
			cache.evictLocked(now)
		}
		previous := int64(0)
		if entry != nil && entry.err == nil {
			previous = entry.revision
		}
		reading := make(chan struct{})
		cache.entries[id] = &flowLogEntry{reading: reading}
		cache.mu.Unlock()
		// The read is every waiting stream's, the first caller's too: it runs
		// on its own deadline, and a caller that gives up only stops waiting
		// (review s4b M1).
		go cache.read(ctx, scope, max(revision, previous), reading)
		select {
		case <-ctx.Done():
			return FlowLogSettings{}, ctx.Err()
		case <-reading:
		}
	}
}

// flowLogReadTimeout bounds a shared read whose first caller set no
// deadline.
const flowLogReadTimeout = 10 * time.Second

// read makes one shared read and answers every stream waiting on it.
func (cache *FlowLogCache) read(ctx context.Context, scope network.Scope, revision int64, reading chan struct{}) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(flowLogReadTimeout)
	}
	readCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	settings, err := cache.reader.ReadFlowLog(readCtx, scope)
	cancel()
	cache.mu.Lock()
	cache.entries[scope.NetworkID()] = &flowLogEntry{revision: revision, readAt: cache.now(), settings: settings, err: err}
	close(reading)
	cache.mu.Unlock()
}

// evictLocked drops every finished entry past its age, or else the oldest
// finished one, so a full cache scans once per FlowLogSettingsAge at most.
func (cache *FlowLogCache) evictLocked(now time.Time) {
	var oldest network.ID
	var oldestAt time.Time
	found := false
	for id, entry := range cache.entries {
		if entry.reading != nil {
			continue
		}
		if now.Sub(entry.readAt) >= FlowLogSettingsAge {
			delete(cache.entries, id)
			continue
		}
		if !found || entry.readAt.Before(oldestAt) {
			oldest, oldestAt, found = id, entry.readAt, true
		}
	}
	if len(cache.entries) >= cache.limit && found {
		delete(cache.entries, oldest)
	}
}

// WithFlowLogs returns a copy of the service that sends FlowTickets to
// nodes whose Network logs connections, reading the settings through
// reader (a FlowLogCache in production) and signing only while gate is
// open (C71).
func (service *StreamService) WithFlowLogs(reader FlowLogReader, gate FlowReceiverGate) (*StreamService, error) {
	if service == nil || isNilDependency(reader) || isNilDependency(gate) {
		return nil, ErrInvalidStreamService
	}
	options := service.options
	options.FlowLogs, options.FlowGate = reader, gate
	logged, err := NewStreamService(service.snapshots, service.presence, service.revisions,
		service.connectivity, options)
	if err != nil {
		return nil, err
	}
	logged.delivery = service.delivery
	logged.enforcement = service.enforcement
	return logged, nil
}

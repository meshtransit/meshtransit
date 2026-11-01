package mapsession

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// flowRecordingSink records the tickets a stream sends.
type flowRecordingSink struct {
	recordingStreamSink
	flowMu  sync.Mutex
	tickets []flowTicketCall
	refuse  bool
	// unsigned answers a zero expiry; fail, an error.
	unsigned bool
	fail     error
}

func (sink *flowRecordingSink) TakesFlowTickets() bool {
	sink.flowMu.Lock()
	defer sink.flowMu.Unlock()
	return !sink.refuse
}

type flowTicketCall struct {
	grant FlowGrant
	on    bool
}

func (sink *flowRecordingSink) SendFlowTicket(_ context.Context, grant FlowGrant, on bool) (time.Time, error) {
	sink.flowMu.Lock()
	defer sink.flowMu.Unlock()
	sink.tickets = append(sink.tickets, flowTicketCall{grant: grant, on: on})
	switch {
	case sink.refuse && on:
		return time.Time{}, ErrNoFlowTickets
	case sink.fail != nil:
		return time.Time{}, sink.fail
	case sink.unsigned || !on:
		return time.Time{}, nil
	}
	return time.Now().Add(15 * time.Minute), nil
}

func (sink *flowRecordingSink) calls() []flowTicketCall {
	sink.flowMu.Lock()
	defer sink.flowMu.Unlock()
	return append([]flowTicketCall(nil), sink.tickets...)
}

// settableFlowLogs answers what the test last set.
type settableFlowLogs struct {
	mu       sync.Mutex
	settings FlowLogSettings
	err      error
	reads    int
}

func (reader *settableFlowLogs) ReadFlowLog(context.Context, network.Scope) (FlowLogSettings, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.reads++
	return reader.settings, reader.err
}

func (reader *settableFlowLogs) set(settings FlowLogSettings, err error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.settings, reader.err = settings, err
}

func serveWithFlowLogs(t *testing.T, reader FlowLogReader, sink *flowRecordingSink, snapshot Snapshot,
) (context.CancelFunc, chan error) {
	t.Helper()
	options := streamOptionsFixture(t)
	options.FlowLogs = reader
	service, err := NewStreamService(&streamSnapshotOpener{snapshots: []Snapshot{snapshot}},
		&streamPresenceStore{}, newStreamRevisionWatcher(), newStreamConnectivityWatcher(), options)
	if err != nil {
		t.Fatalf("NewStreamService() error = %v", err)
	}
	machine, request := authenticatedRequestFixture(t, snapshot)
	ctx, cancel := context.WithCancel(t.Context())
	result := make(chan error, 1)
	go func() { result <- service.Serve(ctx, machine, request, sink) }()
	return cancel, result
}

// A node of a logging Network gets a ticket, a new one at half its life,
// none while nothing changes, and an empty one when logging ends.
func TestStreamSendsAndRenewsFlowTickets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotFixture(t)
		reader := &settableFlowLogs{settings: FlowLogSettings{Enabled: true, WindowSeconds: 120}}
		sink := &flowRecordingSink{}
		cancel, result := serveWithFlowLogs(t, reader, sink, snapshot)

		synctest.Wait()
		calls := sink.calls()
		if len(calls) != 1 || !calls[0].on {
			t.Fatalf("initial tickets = %+v", calls)
		}
		grant := calls[0].grant
		if grant.Scope != snapshot.Scope() || grant.Device != snapshot.NodeID() ||
			grant.MachineKey != snapshot.MachineKey() || len(grant.Roles) != 1 || grant.Roles[0] != FlowRoleDevice ||
			grant.WindowSeconds != 120 || !grant.NotAfter.Equal(snapshot.KeyExpiry()) || grant.Sites != nil {
			t.Fatalf("grant = %+v", grant)
		}

		time.Sleep(5 * time.Minute)
		synctest.Wait()
		if calls := sink.calls(); len(calls) != 1 {
			t.Fatalf("a ticket before half its life: %d", len(calls))
		}
		time.Sleep(3 * time.Minute)
		synctest.Wait()
		if calls := sink.calls(); len(calls) != 2 || !calls[1].on || !calls[1].grant.Equal(grant) {
			t.Fatalf("renewal = %+v", calls)
		}

		// A failed read changes nothing; logging off sends one empty ticket.
		reader.set(FlowLogSettings{}, errors.New("database unavailable"))
		time.Sleep(time.Minute)
		synctest.Wait()
		if calls := sink.calls(); len(calls) != 2 {
			t.Fatalf("a failed read sent %d tickets", len(calls))
		}
		reader.set(FlowLogSettings{Forwarded: true, WindowSeconds: 60}, nil)
		time.Sleep(time.Minute)
		synctest.Wait()
		if calls := sink.calls(); len(calls) != 3 || calls[2].on {
			t.Fatalf("off = %+v", calls)
		}
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if calls := sink.calls(); len(calls) != 3 {
			t.Fatalf("tickets while off: %d", len(calls))
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v", err)
		}
	})
}

// A session that takes no tickets is never asked, and reads nothing.
func TestStreamStopsAskingASessionWithoutFlowTickets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := &settableFlowLogs{settings: FlowLogSettings{Enabled: true, WindowSeconds: 60}}
		sink := &flowRecordingSink{refuse: true}
		cancel, result := serveWithFlowLogs(t, reader, sink, snapshotFixture(t))
		time.Sleep(20 * time.Minute)
		synctest.Wait()
		reader.mu.Lock()
		reads := reader.reads
		reader.mu.Unlock()
		if calls := sink.calls(); len(calls) != 0 || reads != 0 {
			t.Fatalf("asked %d times, read %d times", len(calls), reads)
		}
		cancel()
		synctest.Wait()
		<-result
	})
}

func TestFlowGrantFromSnapshot(t *testing.T) {
	t.Parallel()
	snapshot := snapshotFixture(t)
	if _, on := snapshot.FlowGrant(FlowLogSettings{WindowSeconds: 60}); on {
		t.Error("a Network that does not log grants")
	}
	if _, on := (Snapshot{}).FlowGrant(FlowLogSettings{Enabled: true, WindowSeconds: 60}); on {
		t.Error("an invalid snapshot grants")
	}
	// Forwarded logging adds roles only for what the node serves.
	grant, on := snapshot.FlowGrant(FlowLogSettings{Enabled: true, Forwarded: true, WindowSeconds: 300})
	if !on || len(grant.Roles) != 1 || grant.Sites != nil || grant.ExitPools != nil || grant.WindowSeconds != 300 {
		t.Fatalf("grant = %+v", grant)
	}
	other := grant
	other.WindowSeconds = 60
	if grant.Equal(other) || !grant.Equal(grant) {
		t.Error("Equal")
	}
}

func TestFlowGrantIDs(t *testing.T) {
	t.Parallel()
	low, high := "01890f00-0000-7000-8000-000000000001", "01890f00-0000-7000-8000-000000000002"
	ids, room := flowGrantIDs([]string{high, "not-an-id", low, high}, 64)
	if len(ids) != 2 || room != 62 || ids[0] != mustFlowID(t, low) || ids[1] != mustFlowID(t, high) {
		t.Fatalf("ids = %v, room %d", ids, room)
	}
	if ids, room := flowGrantIDs([]string{high, low}, 1); len(ids) != 1 || room != 0 || ids[0] != mustFlowID(t, low) {
		t.Fatalf("capped ids = %v, room %d", ids, room)
	}
	if ids, room := flowGrantIDs(nil, 3); ids != nil || room != 3 {
		t.Fatalf("no ids = %v, room %d", ids, room)
	}
}

func mustFlowID(t *testing.T, text string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// The cache answers a revision once, again for a newer one or once old,
// never caches a failure, and keeps at most its limit of Networks.
func TestFlowLogCache(t *testing.T) {
	t.Parallel()
	reader := &settableFlowLogs{settings: FlowLogSettings{Enabled: true, WindowSeconds: 60}}
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	cache, err := NewFlowLogCache(reader, 1, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	scope := snapshotFixture(t).Scope()
	read := func(revision int64) FlowLogSettings {
		t.Helper()
		settings, err := cache.ReadFlowLogAt(t.Context(), scope, revision)
		if err != nil {
			t.Fatal(err)
		}
		return settings
	}
	reads := func() int {
		reader.mu.Lock()
		defer reader.mu.Unlock()
		return reader.reads
	}
	first, again, older := read(5), read(5), read(4)
	if !first.Enabled || !again.Enabled || !older.Enabled || reads() != 1 {
		t.Fatalf("reads = %d", reads())
	}
	read(6)
	if reads() != 2 {
		t.Fatalf("a newer revision: reads = %d", reads())
	}
	now = now.Add(FlowLogSettingsAge)
	read(6)
	if reads() != 3 {
		t.Fatalf("an old read: reads = %d", reads())
	}
	reader.set(FlowLogSettings{}, errors.New("unavailable"))
	now = now.Add(FlowLogSettingsAge)
	if _, err := cache.ReadFlowLogAt(t.Context(), scope, 6); err == nil {
		t.Fatal("a failure answered")
	}
	reader.set(FlowLogSettings{WindowSeconds: 60}, nil)
	if _, err := cache.ReadFlowLogAt(t.Context(), scope, 6); err == nil || reads() != 4 {
		t.Fatalf("a fresh failure: reads = %d", reads())
	}
	now = now.Add(flowLogFailureAge)
	if read(6).Enabled || reads() != 5 {
		t.Fatalf("after a failure: reads = %d", reads())
	}
	otherNetwork, err := network.NewScope(scope.WorkspaceID(), network.ID(mustFlowID(t, "01890f00-0000-7000-8000-0000000000aa")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.ReadFlowLogAt(t.Context(), otherNetwork, 1); err != nil {
		t.Fatal(err)
	}
	cache.mu.Lock()
	entries := len(cache.entries)
	cache.mu.Unlock()
	if entries != 1 {
		t.Fatalf("entries = %d, want 1", entries)
	}
	if _, err := NewFlowLogCache(nil, 1, time.Now); err == nil {
		t.Error("a cache without a reader")
	}
}

// A setting change reaches the node within the settings' age; off then on
// is an empty ticket, then a new one; reads follow the age, not the loop.
func TestStreamFollowsFlowLogChanges(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := &settableFlowLogs{settings: FlowLogSettings{Enabled: true, WindowSeconds: 60}}
		sink := &flowRecordingSink{}
		cancel, result := serveWithFlowLogs(t, reader, sink, snapshotFixture(t))
		synctest.Wait()
		reader.set(FlowLogSettings{Enabled: true, WindowSeconds: 300}, nil)
		time.Sleep(FlowLogSettingsAge + time.Second)
		synctest.Wait()
		calls := sink.calls()
		if len(calls) != 2 || calls[1].grant.WindowSeconds != 300 {
			t.Fatalf("change = %+v", calls)
		}
		reader.mu.Lock()
		reads := reader.reads
		reader.mu.Unlock()
		if reads > 3 {
			t.Fatalf("read %d times in a minute", reads)
		}
		reader.set(FlowLogSettings{WindowSeconds: 60}, nil)
		time.Sleep(FlowLogSettingsAge + time.Second)
		reader.set(FlowLogSettings{Enabled: true, WindowSeconds: 60}, nil)
		time.Sleep(FlowLogSettingsAge + time.Second)
		synctest.Wait()
		if calls := sink.calls(); len(calls) != 4 || calls[2].on || !calls[3].on {
			t.Fatalf("off then on = %+v", calls)
		}
		cancel()
		synctest.Wait()
		<-result
	})
}

// A ticket that cannot be sent ends the stream as a write failure.
func TestStreamEndsWhenAFlowTicketCannotBeSent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := &settableFlowLogs{settings: FlowLogSettings{Enabled: true, WindowSeconds: 60}}
		sink := &flowRecordingSink{fail: errors.New("connection reset")}
		cancel, result := serveWithFlowLogs(t, reader, sink, snapshotFixture(t))
		defer cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrStreamWrite) {
			t.Fatalf("Serve() error = %v", err)
		}
	})
}

// When no token can be signed and the node holds one that outlives its
// authority, the stream takes it back.
func TestSyncFlowTicketWithdrawsATokenPastTheAuthority(t *testing.T) {
	t.Parallel()
	options := streamOptionsFixture(t)
	options.FlowLogs = &settableFlowLogs{settings: FlowLogSettings{Enabled: true, WindowSeconds: 60}}
	service, err := NewStreamService(&streamSnapshotOpener{}, &streamPresenceStore{}, newStreamRevisionWatcher(),
		newStreamConnectivityWatcher(), options)
	if err != nil {
		t.Fatal(err)
	}
	current := snapshotFixture(t)
	grant, _ := current.FlowGrant(FlowLogSettings{Enabled: true, WindowSeconds: 60})
	state := flowTicketState{
		read: true, settings: FlowLogSettings{Enabled: true, WindowSeconds: 60},
		readRevision: current.NetworkRevision(), readAt: time.Now(),
		sent: true, grant: FlowGrant{}, expires: grant.Deadline.Add(time.Hour), renewAt: time.Now(),
	}
	sink := &flowRecordingSink{unsigned: true}
	if err := service.syncFlowTicket(t.Context(), sink, current, &state); err != nil {
		t.Fatal(err)
	}
	if calls := sink.calls(); len(calls) != 2 || !calls[0].on || calls[1].on || state.sent {
		t.Fatalf("calls = %+v, sent %v", calls, state.sent)
	}
}

// Forwarded logging names the pools an exit node serves first, then the
// Sites a router serves.
func TestFlowGrantNamesWhatTheNodeServes(t *testing.T) {
	t.Parallel()
	snapshot := snapshotFixture(t)
	site, pool := "01890f00-0000-7000-8000-0000000000b2", "01890f00-0000-7000-8000-0000000000b1"
	snapshot.routes = RouteView{
		served:      []ServedSite{{Ref: site}},
		servedExits: []ServedExit{{Ref: pool}},
	}
	grant, on := snapshot.FlowGrant(FlowLogSettings{Enabled: true, Forwarded: true, WindowSeconds: 60})
	if !on || len(grant.Roles) != 3 || grant.Roles[1] != FlowRoleRouter || grant.Roles[2] != FlowRoleExit ||
		len(grant.Sites) != 1 || grant.Sites[0] != mustFlowID(t, site) ||
		len(grant.ExitPools) != 1 || grant.ExitPools[0] != mustFlowID(t, pool) {
		t.Fatalf("grant = %+v", grant)
	}
	unforwarded, _ := snapshot.FlowGrant(FlowLogSettings{Enabled: true, WindowSeconds: 60})
	if len(unforwarded.Roles) != 1 || unforwarded.Sites != nil {
		t.Fatalf("without forwarded logging = %+v", unforwarded)
	}
	sites := make([]ServedSite, 0, MaximumFlowGrantIDs+1)
	for index := range MaximumFlowGrantIDs + 1 {
		sites = append(sites, ServedSite{Ref: fmt.Sprintf("01890f00-0000-7000-8000-%012x", 0x100+index)})
	}
	snapshot.routes = RouteView{served: sites, servedExits: []ServedExit{{Ref: pool}}}
	full, _ := snapshot.FlowGrant(FlowLogSettings{Enabled: true, Forwarded: true, WindowSeconds: 60})
	if len(full.ExitPools) != 1 || len(full.Sites) != MaximumFlowGrantIDs-1 {
		t.Fatalf("a full grant: %d pools, %d Sites", len(full.ExitPools), len(full.Sites))
	}
}

// blockingFlowLogs holds each read until released.
type blockingFlowLogs struct {
	release chan struct{}
	err     error
	mu      sync.Mutex
	reads   int
}

func (reader *blockingFlowLogs) ReadFlowLog(ctx context.Context, _ network.Scope) (FlowLogSettings, error) {
	reader.mu.Lock()
	reader.reads++
	reader.mu.Unlock()
	select {
	case <-reader.release:
	case <-ctx.Done():
		return FlowLogSettings{}, ctx.Err()
	}
	return FlowLogSettings{Enabled: reader.err == nil, WindowSeconds: 60}, reader.err
}

// Streams waiting on a read share it, its failure too, which answers for a
// few seconds; a waiter that gives up leaves; the revision never drops.
func TestFlowLogCacheSharesReads(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := &blockingFlowLogs{release: make(chan struct{})}
		cache, err := NewFlowLogCache(reader, 8, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		scope := snapshotFixture(t).Scope()
		results := make(chan error, 3)
		for range 3 {
			go func() {
				_, err := cache.ReadFlowLogAt(t.Context(), scope, 4)
				results <- err
			}()
		}
		waiting, cancelWait := context.WithCancel(t.Context())
		gaveUp := make(chan error, 1)
		go func() {
			_, err := cache.ReadFlowLogAt(waiting, scope, 4)
			gaveUp <- err
		}()
		synctest.Wait()
		cancelWait()
		if err := <-gaveUp; !errors.Is(err, context.Canceled) {
			t.Fatalf("a waiter that gave up: %v", err)
		}
		reader.err = errors.New("unavailable")
		close(reader.release)
		for range 3 {
			if err := <-results; err == nil {
				t.Fatal("a waiter missed the failure")
			}
		}
		if _, err := cache.ReadFlowLogAt(t.Context(), scope, 4); err == nil {
			t.Fatal("a fresh failure was read again")
		}
		reader.mu.Lock()
		reads := reader.reads
		reader.mu.Unlock()
		if reads != 1 {
			t.Fatalf("reads = %d", reads)
		}
		time.Sleep(flowLogFailureAge)
		reader.err = nil
		if _, err := cache.ReadFlowLogAt(t.Context(), scope, 9); err != nil {
			t.Fatal(err)
		}
		if _, err := cache.ReadFlowLogAt(t.Context(), scope, 9); err != nil {
			t.Fatal(err)
		}
		time.Sleep(FlowLogSettingsAge)
		if _, err := cache.ReadFlowLogAt(t.Context(), scope, 3); err != nil {
			t.Fatal(err)
		}
		cache.mu.Lock()
		revision := cache.entries[scope.NetworkID()].revision
		cache.mu.Unlock()
		if revision != 9 {
			t.Fatalf("revision = %d, want 9", revision)
		}
	})
}

func newFlowSyncService(t *testing.T, reader FlowLogReader) *StreamService {
	t.Helper()
	options := streamOptionsFixture(t)
	options.FlowLogs = reader
	service, err := NewStreamService(&streamSnapshotOpener{}, &streamPresenceStore{}, newStreamRevisionWatcher(),
		newStreamConnectivityWatcher(), options)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

// A renewal due while a read just failed signs nothing from the settings
// read before (review s4b H1).
func TestSyncFlowTicketSignsNothingAfterAFailedRead(t *testing.T) {
	synctest.Test(t, syncFlowTicketAfterAFailedRead)
}

func syncFlowTicketAfterAFailedRead(t *testing.T) {
	reader := &settableFlowLogs{settings: FlowLogSettings{Enabled: true, WindowSeconds: 60}}
	service := newFlowSyncService(t, reader)
	current := snapshotFixture(t)
	sink := &flowRecordingSink{}
	var state flowTicketState
	if err := service.syncFlowTicket(t.Context(), sink, current, &state); err != nil || !state.sent {
		t.Fatalf("first sync: %v, sent %v", err, state.sent)
	}
	state.renewAt = time.Now().Add(-time.Second)
	reader.set(FlowLogSettings{}, errors.New("unavailable"))
	for range 3 {
		if err := service.syncFlowTicket(t.Context(), sink, current, &state); err != nil {
			t.Fatal(err)
		}
	}
	if calls := sink.calls(); len(calls) != 1 {
		t.Fatalf("signed from stale settings: %+v", calls)
	}
	// Stale settings after a revision move sign nothing either.
	state.failedAt = time.Time{}
	state.readRevision--
	reader.set(FlowLogSettings{}, errors.New("unavailable"))
	if err := service.syncFlowTicket(t.Context(), sink, current, &state); err != nil || len(sink.calls()) != 1 {
		t.Fatalf("after a revision move: %v, %d calls", err, len(sink.calls()))
	}
}

// A session that stops taking tickets gives back the one it holds.
func TestSyncFlowTicketWithdrawsWhenTheSessionStopsTakingTickets(t *testing.T) {
	synctest.Test(t, syncFlowTicketWhenTheSessionStops)
}

func syncFlowTicketWhenTheSessionStops(t *testing.T) {
	service := newFlowSyncService(t, &settableFlowLogs{settings: FlowLogSettings{Enabled: true, WindowSeconds: 60}})
	current := snapshotFixture(t)
	sink := &flowRecordingSink{}
	var state flowTicketState
	if err := service.syncFlowTicket(t.Context(), sink, current, &state); err != nil {
		t.Fatal(err)
	}
	sink.flowMu.Lock()
	sink.refuse = true
	sink.flowMu.Unlock()
	if err := service.syncFlowTicket(t.Context(), sink, current, &state); err != nil {
		t.Fatal(err)
	}
	if calls := sink.calls(); len(calls) != 2 || calls[1].on || !state.refused || state.sent {
		t.Fatalf("calls = %+v, state %+v", calls, state)
	}
}

// A stream that ends while its read is shared fails no other stream's read
// (review s4b M1).
func TestFlowLogCacheReadOutlivesItsCaller(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := &blockingFlowLogs{release: make(chan struct{})}
		cache, err := NewFlowLogCache(reader, 8, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		scope := snapshotFixture(t).Scope()
		first, cancelFirst := context.WithCancel(t.Context())
		gaveUp := make(chan error, 1)
		go func() {
			_, err := cache.ReadFlowLogAt(first, scope, 1)
			gaveUp <- err
		}()
		waiter := make(chan error, 1)
		synctest.Wait()
		go func() {
			_, err := cache.ReadFlowLogAt(t.Context(), scope, 1)
			waiter <- err
		}()
		synctest.Wait()
		cancelFirst()
		synctest.Wait()
		close(reader.release)
		<-gaveUp
		if err := <-waiter; err != nil {
			t.Fatalf("the other stream's read failed: %v", err)
		}
	})
}

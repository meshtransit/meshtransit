package mapsession

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// settableGate is a FlowReceiverGate a test opens and closes.
type settableGate struct {
	mu       sync.Mutex
	open     bool
	openedAt time.Time
	withheld int
}

func (gate *settableGate) FlowGate(context.Context) FlowGateState {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return FlowGateState{Open: gate.open, OpenedAt: gate.openedAt, Until: time.Now().Add(FlowGateAge)}
}

func (gate *settableGate) Withheld() {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	gate.withheld++
}

func (gate *settableGate) set(open bool, openedAt time.Time) {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	gate.open, gate.openedAt = open, openedAt
}

func serveWithFlowGate(t *testing.T, reader FlowLogReader, gate FlowReceiverGate, sink *flowRecordingSink,
) (context.CancelFunc, chan error) {
	t.Helper()
	snapshot := snapshotFixture(t)
	options := streamOptionsFixture(t)
	options.FlowLogs, options.FlowGate = reader, gate
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

func stopStream(t *testing.T, cancel context.CancelFunc, result chan error) {
	t.Helper()
	cancel()
	synctest.Wait()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("Serve() error = %v", err)
	}
}

// A closed gate signs nothing; once it opens, the first ticket goes at the
// Device's place in the minute's spread (C71).
func TestFlowGateHoldsFirstTickets(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := &settableFlowLogs{settings: FlowLogSettings{Enabled: true, WindowSeconds: 60}}
		gate := &settableGate{}
		sink := &flowRecordingSink{}
		cancel, result := serveWithFlowGate(t, reader, gate, sink)
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if calls := sink.calls(); len(calls) != 0 || gate.withheld == 0 {
			t.Fatalf("a closed gate sent %d tickets, withheld %d", len(calls), gate.withheld)
		}
		gate.set(true, time.Now())
		time.Sleep(FlowGateAge + flowGateSpread)
		synctest.Wait()
		if calls := sink.calls(); len(calls) != 1 || !calls[0].on {
			t.Fatalf("after the gate opened: %+v", calls)
		}
		stopStream(t, cancel, result)
	})
}

// A closed gate keeps the ticket a node holds while its grant stands, never
// renews it, and withdraws it when the grant changes; turning logging off
// still sends the empty ticket (C71).
func TestFlowGateKeepsWithdrawsAndTurnsOff(t *testing.T) {
	for name, change := range map[string]FlowLogSettings{
		"grant changed": {Enabled: true, WindowSeconds: 120},
		"logging off":   {},
	} {
		t.Run(name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				reader := &settableFlowLogs{settings: FlowLogSettings{Enabled: true, WindowSeconds: 60}}
				gate := &settableGate{open: true, openedAt: time.Now().Add(-time.Hour)}
				sink := &flowRecordingSink{}
				cancel, result := serveWithFlowGate(t, reader, gate, sink)
				synctest.Wait()
				if calls := sink.calls(); len(calls) != 1 || !calls[0].on {
					t.Fatalf("an open gate: %+v", calls)
				}
				gate.set(false, time.Time{})
				time.Sleep(10 * time.Minute)
				synctest.Wait()
				if calls := sink.calls(); len(calls) != 1 {
					t.Fatalf("a closed gate renewed: %+v", calls)
				}
				reader.set(change, nil)
				time.Sleep(2 * time.Minute)
				synctest.Wait()
				if calls := sink.calls(); len(calls) != 2 || calls[1].on {
					t.Fatalf("%s under a closed gate: %+v", name, calls)
				}
				stopStream(t, cancel, result)
			})
		})
	}
}

// Tickets kept while the gate was closed are renewed at each Device's place
// in the spread after it reopens, not all at once (review s4c3 H1).
func TestFlowGateSpreadsRenewalsAfterReopening(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := &settableFlowLogs{settings: FlowLogSettings{Enabled: true, WindowSeconds: 60}}
		gate := &settableGate{open: true, openedAt: time.Now().Add(-time.Hour)}
		sink := &flowRecordingSink{}
		cancel, result := serveWithFlowGate(t, reader, gate, sink)
		synctest.Wait()
		gate.set(false, time.Time{})
		time.Sleep(20 * time.Minute)
		synctest.Wait()
		if calls := sink.calls(); len(calls) != 1 || gate.withheld != 1 {
			t.Fatalf("a closed spell: %d tickets, withheld %d", len(calls), gate.withheld)
		}
		reopened := time.Now()
		gate.set(true, reopened)
		delay := flowGateDelay(snapshotFixture(t).NodeID())
		if delay > time.Millisecond {
			time.Sleep(delay - time.Millisecond)
			synctest.Wait()
			if calls := sink.calls(); len(calls) != 1 {
				t.Fatalf("renewed %v after reopening, before its place %v", time.Since(reopened), delay)
			}
		}
		time.Sleep(FlowGateAge + time.Second)
		synctest.Wait()
		if calls := sink.calls(); len(calls) != 2 || !calls[1].on {
			t.Fatalf("after its place: %+v", calls)
		}
		stopStream(t, cancel, result)
	})
}

type countingGateReader struct {
	mu    sync.Mutex
	reads int
	gate  connectionlog.ReceiverGate
	err   error
}

func (reader *countingGateReader) ReadFlowGate(context.Context) (connectionlog.ReceiverGate, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.reads++
	return reader.gate, reader.err
}

// The cache reads once per FlowGateAge, answers closed on a failed read and
// notes when it saw the gate open again.
func TestFlowGateCache(t *testing.T) {
	t.Parallel()
	moment := time.Unix(1_900_000_000, 0)
	now := func() time.Time { return moment }
	reader := &countingGateReader{gate: connectionlog.ReceiverGate{Fresh: 2, Accepting: 1}}
	cache, err := NewFlowGateCache(reader, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFlowGateCache(nil, now); err == nil {
		t.Fatal("built without a reader")
	}
	ctx := t.Context()
	if state := cache.FlowGate(ctx); !state.Open || !state.OpenedAt.Equal(moment) ||
		!state.Until.Equal(moment.Add(FlowGateAge)) {
		t.Fatalf("first read = %+v", state)
	}
	moment = moment.Add(FlowGateAge - time.Second)
	cache.FlowGate(ctx)
	if reader.reads != 1 {
		t.Fatalf("read %d times within the age", reader.reads)
	}
	moment = moment.Add(time.Second)
	reader.err = errors.New("database down")
	if state := cache.FlowGate(ctx); state.Open || reader.reads != 2 || !cache.Snapshot().Failed {
		t.Fatalf("a failed read = %+v", state)
	}
	moment = moment.Add(FlowGateAge)
	reader.err, reader.gate = nil, connectionlog.ReceiverGate{Fresh: 1}
	if state := cache.FlowGate(ctx); state.Open {
		t.Fatalf("no receiver accepts, yet %+v", state)
	}
	moment = moment.Add(FlowGateAge)
	reader.gate.Accepting = 1
	if state := cache.FlowGate(ctx); !state.Open || !state.OpenedAt.Equal(moment) {
		t.Fatalf("reopened = %+v", state)
	}
	cache.Withheld()
	if snapshot := cache.Snapshot(); snapshot.Withheld != 1 || !snapshot.Open || snapshot.Gate.Accepting != 1 {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestFlowGateDelaySpreadsDevices(t *testing.T) {
	t.Parallel()
	seen := map[time.Duration]bool{}
	for index := range 50 {
		id, err := publicid.Parse(fmt.Sprintf("01890f00-0000-7000-8000-%012x", index))
		if err != nil {
			t.Fatal(err)
		}
		delay := flowGateDelay(node.ID(id))
		if delay < 0 || delay >= flowGateSpread {
			t.Fatalf("delay %v", delay)
		}
		seen[delay] = true
	}
	if len(seen) < 40 {
		t.Fatalf("only %d distinct delays", len(seen))
	}
}

// The gate opens for a Network only when every accepting receiver writes
// to its type (schema 273); no credential is never held by type.
func TestFlowGateStateWrites(t *testing.T) {
	t.Parallel()
	open := FlowGateState{Open: true, DestinationTypes: []string{"aws_s3", "cloudflare_r2"}}
	if !open.Writes("aws_s3") || open.Writes("datadog") || !open.Writes("") {
		t.Fatalf("open gate: %+v", open)
	}
	if (FlowGateState{DestinationTypes: []string{"datadog"}}).Writes("datadog") {
		t.Fatal("a closed gate wrote")
	}
}

// A type that joins the receivers' types after the gate opened opens then,
// so its Devices' tickets are spread from that moment; a type kept keeps
// its time, one that leaves forgets it (review p1c M2).
func TestFlowGateTypeOpenedAt(t *testing.T) {
	t.Parallel()
	moment := time.Unix(1_900_000_000, 0)
	reader := &countingGateReader{gate: connectionlog.ReceiverGate{
		Fresh: 1, Accepting: 1, DestinationTypes: []string{"aws_s3"},
	}}
	cache, err := NewFlowGateCache(reader, func() time.Time { return moment })
	if err != nil {
		t.Fatal(err)
	}
	opened := moment
	cache.FlowGate(t.Context())
	moment = moment.Add(FlowGateAge)
	reader.gate.DestinationTypes = []string{"aws_s3", "datadog"}
	state := cache.FlowGate(t.Context())
	if !state.OpenedAtFor("aws_s3").Equal(opened) || !state.OpenedAtFor("datadog").Equal(moment) ||
		!state.OpenedAtFor("").Equal(opened) {
		t.Fatalf("types joined = %+v", state)
	}
	moment = moment.Add(FlowGateAge)
	reader.gate.DestinationTypes = []string{"aws_s3"}
	if state := cache.FlowGate(t.Context()); state.Writes("datadog") || len(state.TypeOpenedAt) != 1 {
		t.Fatalf("a type left = %+v", state)
	}
}

package mapsession

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

type recordingDeliveryRecorder struct {
	mu         sync.Mutex
	deliveries []Delivery
	touches    []time.Time
	fail       bool
}

func (recorder *recordingDeliveryRecorder) RecordDelivery(ctx context.Context, delivery Delivery) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if _, bounded := ctx.Deadline(); !bounded {
		return errors.New("unbounded delivery record")
	}
	recorder.deliveries = append(recorder.deliveries, delivery)
	if recorder.fail {
		return errors.New("synthetic delivery store failure")
	}
	return nil
}

func (recorder *recordingDeliveryRecorder) TouchDelivery(
	ctx context.Context,
	_ node.ID,
	_ int64,
	seenAt time.Time,
) error {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if _, bounded := ctx.Deadline(); !bounded {
		return errors.New("unbounded delivery touch")
	}
	recorder.touches = append(recorder.touches, seenAt)
	return nil
}

func (recorder *recordingDeliveryRecorder) state() ([]Delivery, []time.Time) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]Delivery(nil), recorder.deliveries...), append([]time.Time(nil), recorder.touches...)
}

func serveWithDelivery(
	t *testing.T,
	recorder *recordingDeliveryRecorder,
) (initial Snapshot, advanced Snapshot, revisions *streamRevisionWatcher, sink *recordingStreamSink,
	cancel context.CancelFunc, result chan error) {
	t.Helper()
	initial, advanced, _ = authorityDeltaSnapshotsFixture(t)
	opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, advanced}}
	revisions = newStreamRevisionWatcher()
	base := newStreamServiceWithRevisionsFixture(t, opener, &streamPresenceStore{}, revisions)
	service, err := base.WithDeliveryRecorder(recorder)
	if err != nil {
		t.Fatalf("WithDeliveryRecorder() error = %v", err)
	}
	machine, request := authenticatedRequestFixture(t, initial)
	sink = &recordingStreamSink{}
	var ctx context.Context
	ctx, cancel = context.WithCancel(t.Context())
	result = make(chan error, 1)
	go func() { result <- service.Serve(ctx, machine, request, sink) }()
	return initial, advanced, revisions, sink, cancel, result
}

func advanceRevision(t *testing.T, revisions *streamRevisionWatcher, initial, advanced Snapshot) {
	t.Helper()
	wakeup, err := network.NewRevisionAdvanced(initial.Scope().NetworkID().String(), advanced.NetworkRevision())
	if err != nil {
		t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
	}
	revisions.send(t, wakeup)
}

func TestStreamServiceRecordsEachDeliveredNetworkRevision(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		recorder := &recordingDeliveryRecorder{}
		initial, advanced, revisions, _, cancel, result := serveWithDelivery(t, recorder)

		synctest.Wait()
		deliveries, _ := recorder.state()
		if len(deliveries) != 1 || deliveries[0].NodeID != initial.NodeID() ||
			deliveries[0].NetworkRevision != initial.NetworkRevision() ||
			deliveries[0].PolicyRevision != initial.PacketPolicy().Revision() ||
			deliveries[0].SessionGeneration != initial.SessionGeneration() ||
			!deliveries[0].IsValid() {
			t.Fatalf("initial deliveries = %+v", deliveries)
		}

		advanceRevision(t, revisions, initial, advanced)
		synctest.Wait()
		deliveries, _ = recorder.state()
		if len(deliveries) != 2 || deliveries[1].NetworkRevision != advanced.NetworkRevision() {
			t.Fatalf("deliveries after advance = %+v", deliveries)
		}

		// Keepalives and reconciles that send nothing new record nothing.
		time.Sleep(20 * time.Second)
		synctest.Wait()
		if deliveries, _ = recorder.state(); len(deliveries) != 2 {
			t.Fatalf("idle stream recorded %d deliveries, want 2", len(deliveries))
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	})
}

func TestStreamServiceKeepsServingWhenDeliveryRecordingFails(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		recorder := &recordingDeliveryRecorder{fail: true}
		initial, advanced, revisions, sink, cancel, result := serveWithDelivery(t, recorder)

		synctest.Wait()
		advanceRevision(t, revisions, initial, advanced)
		synctest.Wait()
		if deltas := sink.authorityDeltaSnapshots(); len(deltas) != 1 {
			t.Fatalf("a failing delivery store stopped the stream: %d deltas", len(deltas))
		}
		select {
		case err := <-result:
			t.Fatalf("Serve() ended early: %v", err)
		default:
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	})
}

func TestStreamServiceTouchesDeliveryAtMostOncePerInterval(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		recorder := &recordingDeliveryRecorder{}
		_, _, _, _, cancel, result := serveWithDelivery(t, recorder)

		synctest.Wait()
		// Presence renews every 3 seconds in the fixture; seen time is kept at
		// most once per DeliveryTouchInterval.
		time.Sleep(DeliveryTouchInterval*2 + time.Second)
		synctest.Wait()
		_, touches := recorder.state()
		if len(touches) != 2 {
			t.Fatalf("touches = %d over two intervals, want 2", len(touches))
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
	})
}

func TestWithDeliveryRecorderRejectsNil(t *testing.T) {
	service := newStreamServiceFixture(t, &streamSnapshotOpener{}, &streamPresenceStore{})
	if _, err := service.WithDeliveryRecorder(nil); !errors.Is(err, ErrInvalidStreamService) {
		t.Fatalf("WithDeliveryRecorder(nil) error = %v", err)
	}
}

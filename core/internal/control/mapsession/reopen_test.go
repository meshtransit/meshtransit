package mapsession

import (
	"context"
	"testing"

	"meshtransit.net/core/internal/control"
)

// aliasObservingStore counts client-compatibility writes.
type aliasObservingStore struct {
	recordingSnapshotStore
	observations int
}

func (store *aliasObservingStore) ObserveDeviceAliasVersion(context.Context, control.AuthenticatedNode, uint8) error {
	store.observations++
	return nil
}

// A stream refresh re-reads authority but does not write the client's
// compatibility claim again: it is recorded once per session, on Open.
func TestServiceReopenSkipsTheCompatibilityWrite(t *testing.T) {
	t.Parallel()
	snapshot := snapshotFixture(t)
	store := &aliasObservingStore{recordingSnapshotStore: recordingSnapshotStore{snapshot: snapshot}}
	service := newServiceFixture(t, store, &recordingEndpointObserver{})
	machine, request := authenticatedRequestFixture(t, snapshot)

	if _, err := service.Open(t.Context(), machine, request); err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	for range 3 {
		if _, err := service.Reopen(t.Context(), machine, request); err != nil {
			t.Fatalf("Reopen() error = %v", err)
		}
	}
	if store.observations != 1 || store.calls != 4 {
		t.Fatalf("observations = %d, loads = %d; want 1 and 4", store.observations, store.calls)
	}
}

// The first delivery record is written right after the frame; the stream
// may end at once (a client that disconnects after its first map), and the
// record must still be written rather than canceled with the stream.
func TestRecordDeliveryOutlivesTheStreamContext(t *testing.T) {
	t.Parallel()
	initial, _, _ := authorityDeltaSnapshotsFixture(t)
	recorder := &cancelAwareRecorder{}
	base := newStreamServiceWithRevisionsFixture(t, &streamSnapshotOpener{snapshots: []Snapshot{initial}},
		&streamPresenceStore{}, newStreamRevisionWatcher())
	service, err := base.WithDeliveryRecorder(recorder)
	if err != nil {
		t.Fatalf("WithDeliveryRecorder() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	service.recordDelivery(ctx, initial, FilterDigest{})
	if recorder.calls != 1 || recorder.canceled {
		t.Fatalf("record calls = %d, canceled = %t; want one live record", recorder.calls, recorder.canceled)
	}
}

type cancelAwareRecorder struct {
	recordingDeliveryRecorder
	calls    int
	canceled bool
}

func (recorder *cancelAwareRecorder) RecordDelivery(ctx context.Context, delivery Delivery) error {
	recorder.calls++
	recorder.canceled = ctx.Err() != nil
	return recorder.recordingDeliveryRecorder.RecordDelivery(ctx, delivery)
}

// viewCheckingStore answers Unchanged and counts Derive and Load calls.
type viewCheckingStore struct {
	recordingSnapshotStore
	unchanged bool
	derives   int
	checks    int
}

func (store *viewCheckingStore) Unchanged(context.Context, Snapshot, int64) (bool, error) {
	store.checks++
	return store.unchanged, nil
}

func (store *viewCheckingStore) Derive(_ context.Context, current Snapshot, _ int64) (Snapshot, bool, error) {
	store.derives++
	return current, true, nil
}

// A reconcile whose Network view did not change keeps the snapshot and
// reads neither the Device nor the view.
func TestServiceRefreshKeepsASnapshotWhoseViewDidNotChange(t *testing.T) {
	t.Parallel()
	snapshot := snapshotFixture(t)
	store := &viewCheckingStore{recordingSnapshotStore: recordingSnapshotStore{snapshot: snapshot}, unchanged: true}
	service := newServiceFixture(t, store, &recordingEndpointObserver{})
	machine, request := authenticatedRequestFixture(t, snapshot)
	current, err := service.Open(t.Context(), machine, request)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	refreshed, err := service.Refresh(t.Context(), machine, request, current, 0)
	if err != nil || !refreshed.IsValid() || store.checks != 1 || store.derives != 0 || store.calls != 1 {
		t.Fatalf("Refresh() = %v; checks %d, derives %d, loads %d", err, store.checks, store.derives, store.calls)
	}
	store.unchanged = false
	if _, err := service.Refresh(t.Context(), machine, request, current, 0); err != nil || store.derives != 1 {
		t.Fatalf("a changed view did not derive: %v, %d derives", err, store.derives)
	}
}

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

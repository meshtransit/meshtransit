package mapsession

import (
	"context"
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/node"
)

func TestServiceLoadsSnapshotForBoundIdentity(t *testing.T) {
	snapshot := snapshotFixture(t)
	store := &recordingSnapshotStore{snapshot: snapshot}
	service, err := NewService(store)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	machine, request := authenticatedRequestFixture(t, snapshot)

	got, err := service.Open(context.Background(), machine, request)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if !got.IsValid() || got.NodeID() != snapshot.NodeID() {
		t.Fatalf("Open() snapshot = %+v, want validated fixture", got)
	}
	if !store.identity.IsValid() || store.identity.NodeKey() != request.NodeKey() ||
		store.identity.MachineFingerprint() != snapshot.MachineKey().Fingerprint() {
		t.Fatalf("store identity was not bound to authenticated request")
	}
}

func TestServiceFailsClosedOnMismatchedSnapshot(t *testing.T) {
	snapshot := snapshotFixture(t)
	params := snapshot.params()
	params.NodeKey, _ = node.NewKey([32]byte{9})
	mismatched, err := NewSnapshot(params)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	service, err := NewService(&recordingSnapshotStore{snapshot: mismatched})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	machine, request := authenticatedRequestFixture(t, snapshot)

	if _, err := service.Open(context.Background(), machine, request); !errors.Is(err, ErrOpen) {
		t.Fatalf("Open() error = %v, want ErrOpen", err)
	}
}

func TestServicePropagatesCancellationWithoutStorageCall(t *testing.T) {
	snapshot := snapshotFixture(t)
	store := &recordingSnapshotStore{snapshot: snapshot}
	service, err := NewService(store)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	machine, request := authenticatedRequestFixture(t, snapshot)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := service.Open(ctx, machine, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("Open() error = %v, want context cancellation", err)
	}
	if store.calls != 0 {
		t.Fatalf("storage calls = %d, want zero", store.calls)
	}
}

func authenticatedRequestFixture(
	t *testing.T,
	snapshot Snapshot,
) (control.AuthenticatedMachine, Request) {
	t.Helper()
	machine, err := control.NewAuthenticatedMachine(snapshot.MachineKey())
	if err != nil {
		t.Fatalf("control.NewAuthenticatedMachine() error = %v", err)
	}
	request, err := NewRequest(snapshot.NodeKey(), 142)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	return machine, request
}

type recordingSnapshotStore struct {
	snapshot Snapshot
	err      error
	identity control.AuthenticatedNode
	calls    int
}

func (store *recordingSnapshotStore) Load(
	_ context.Context,
	identity control.AuthenticatedNode,
) (Snapshot, error) {
	store.calls++
	store.identity = identity
	return store.snapshot, store.err
}

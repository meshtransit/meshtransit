package lifecycle

import (
	"context"
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// operatorStore adds data key changes to the fake store.
type operatorStore struct {
	*fakeStore
	rewrapped []publicid.ID
	retired   []publicid.ID
}

func (store *operatorStore) RewrapDataKey(_ context.Context, _ deployment.ID, _ network.Scope, id publicid.ID,
	version int64, wrapped kubeca.WrappedKey, operator kubeca.Operator,
) error {
	if operator.IsWorker() {
		return errors.New("the worker rewrapped")
	}
	for index := range store.read.DataKeys {
		key := &store.read.DataKeys[index]
		if key.ID == id && key.Version == version {
			key.Version, key.Wrapped = version+1, wrapped
			store.rewrapped = append(store.rewrapped, id)
			return nil
		}
	}
	return errors.New("stale")
}

func (store *operatorStore) RotateDataKey(_ context.Context, _ deployment.ID, _ network.Scope, old publicid.ID,
	version int64, id publicid.ID, wrapped kubeca.WrappedKey, operator kubeca.Operator,
) error {
	if operator.IsWorker() {
		return errors.New("the worker rotated")
	}
	for index := range store.read.DataKeys {
		key := &store.read.DataKeys[index]
		if key.ID == old && key.Version == version && key.Active {
			key.Version, key.Active = version+1, false
			store.retired = append(store.retired, old)
			store.added = append(store.added, id)
			store.read.DataKeys = append(store.read.DataKeys, kubeca.StoredDataKey{
				ID: id, Version: 1,
				Wrapped: wrapped, Active: true,
			})
			return nil
		}
	}
	return errors.New("stale")
}

// rewrapCustody opens what sealingCustody wrapped and wraps under key k2.
type rewrapCustody struct{ sealingCustody }

func (custody rewrapCustody) WrapDataKey(context.Context, string, kubeca.DataKey) (kubeca.WrappedKey, error) {
	return kubeca.WrappedKey{Custody: "file", KeyID: "k2", Ciphertext: []byte("wrapped")}, nil
}

var alice = kubeca.Operator{Name: "alice", ChangeRef: "CHG-1"}

// Every data key of a Network not yet under the custody's current key is
// wrapped again; one already under it is left alone.
func TestRewrapWrapsEveryOlderDataKey(t *testing.T) {
	t.Parallel()
	read, _ := newNetwork(t,
		kubeca.StoredDataKey{
			ID: testID(t), Version: 1, Active: true,
			Wrapped: kubeca.WrappedKey{Custody: "file", KeyID: "k1", Ciphertext: []byte("wrapped")},
		},
		kubeca.StoredDataKey{
			ID: testID(t), Version: 3,
			Wrapped: kubeca.WrappedKey{Custody: "file", KeyID: "k2", Ciphertext: []byte("wrapped")},
		})
	store := &operatorStore{fakeStore: &fakeStore{read: read, scope: testScope(t)}}
	installation, err := deployment.ParseID(testID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	count, err := Rewrap(t.Context(), store, rewrapCustody{}, installation, store.scope, alice)
	if err != nil || count != 1 || len(store.rewrapped) != 1 || store.rewrapped[0] != read.DataKeys[0].ID {
		t.Fatalf("Rewrap() = %d, %v, rewrapped %v", count, err, store.rewrapped)
	}
	if _, err := Rewrap(t.Context(), store, rewrapCustody{}, installation, store.scope, kubeca.Operator{}); err == nil {
		t.Fatal("a rewrap without an operator")
	}
}

// Rotating the data key retires the active one and adds a new one.
func TestRotateDataKey(t *testing.T) {
	t.Parallel()
	read, _ := newNetwork(t, kubeca.StoredDataKey{
		ID: testID(t), Version: 2, Active: true,
		Wrapped: kubeca.WrappedKey{Custody: "file", KeyID: "k1", Ciphertext: []byte("wrapped")},
	})
	store := &operatorStore{fakeStore: &fakeStore{read: read, scope: testScope(t)}}
	installation, err := deployment.ParseID(testID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	added, err := RotateDataKey(t.Context(), store, sealingCustody{}, installation, store.scope, alice)
	if err != nil || len(store.retired) != 1 || store.retired[0] != read.DataKeys[0].ID || len(store.added) != 1 ||
		store.added[0] != added {
		t.Fatalf("RotateDataKey() = %s, %v, retired %v, added %v", added, err, store.retired, store.added)
	}
}

// Retiring a root retires its intermediates first, by the operator; the
// worker then replaces them.
func TestRetireCA(t *testing.T) {
	t.Parallel()
	read, cluster := newNetwork(t)
	rootCA := root(t, kubeca.StateActive, testName, -day, 9*365*day)
	active := intermediate(t, kubeca.StateActive, rootCA, -day, 20*day)
	old := retiringSince(intermediate(t, kubeca.StateRetiring, rootCA, -20*day, 5*day), 2*day)
	read.Clusters[0].CAs = []kubeca.StoredCA{rootCA, active, old}
	store := &operatorStore{fakeStore: &fakeStore{read: read, scope: testScope(t)}}
	installation, err := deployment.ParseID(testID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	if err := RetireCA(t.Context(), store, installation, store.scope, rootCA.ID, kubeca.ReasonCompromise,
		alice); err != nil {
		t.Fatal(err)
	}
	changes := store.changes[0]
	if changes.Operator != alice || len(changes.Steps) != 3 || changes.Steps[0].Move.CA != active.ID ||
		changes.Steps[1].Move.CA != old.ID || changes.Steps[2].Move.CA != rootCA.ID ||
		len(changes.Schedules) != 1 || changes.Schedules[0].Cluster != cluster {
		t.Fatalf("changes = %+v", changes)
	}
	for _, step := range changes.Steps {
		if step.Move.To != kubeca.StateRetired || step.Move.Reason != kubeca.ReasonCompromise {
			t.Fatalf("step %+v", step.Move)
		}
	}
	store.busy = true
	if err := RetireCA(t.Context(), store, installation, store.scope, rootCA.ID, kubeca.ReasonCompromise,
		alice); !errors.Is(err, ErrBusy) {
		t.Fatalf("a busy Network reported %v", err)
	}
	store.busy = false
	for name, retire := range map[string]func() error{
		"unknown CA": func() error {
			return RetireCA(t.Context(), store, installation, store.scope, testID(t), kubeca.ReasonAdmin, alice)
		},
		"no operator": func() error {
			return RetireCA(t.Context(), store, installation, store.scope, rootCA.ID, kubeca.ReasonAdmin,
				kubeca.Operator{})
		},
		"a scheduled reason": func() error {
			return RetireCA(t.Context(), store, installation, store.scope, rootCA.ID, kubeca.ReasonScheduled, alice)
		},
	} {
		if err := retire(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

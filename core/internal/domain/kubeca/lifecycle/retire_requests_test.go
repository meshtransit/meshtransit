package lifecycle

import (
	"context"
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

type fakeRetireQueue struct {
	queue   RetireQueue
	refused map[publicid.ID]string
	listErr error
}

func (queue *fakeRetireQueue) List(context.Context, deployment.ID, int) (RetireQueue, error) {
	return queue.queue, queue.listErr
}

func (queue *fakeRetireQueue) Refuse(_ context.Context, _ deployment.ID, _ network.Scope, request publicid.ID,
	refusal string) (bool, error) {
	if queue.refused == nil {
		queue.refused = map[publicid.ID]string{}
	}
	queue.refused[request] = refusal
	return true, nil
}

// retireFixture is a Network with one cluster holding a root and the
// intermediate it issued, and a request to retire the root.
func retireFixture(t *testing.T) (*fakeStore, *fakeRetireQueue, *Worker, kubeca.RetireRequest) {
	t.Helper()
	read, cluster := newNetwork(t)
	root, intermediate := testID(t), testID(t)
	read.Clusters[0].CAs = []kubeca.StoredCA{
		{ID: root, Version: 3, Kind: kubeca.KindRoot, State: kubeca.StateActive},
		{ID: intermediate, Version: 2, Kind: kubeca.KindIntermediate, IssuerID: root, State: kubeca.StateActive},
	}
	scope := testScope(t)
	store := &fakeStore{read: read, scope: scope}
	request := kubeca.RetireRequest{Scope: scope, Cluster: cluster, ID: testID(t), CA: root, CAVersion: 3,
		CAState: kubeca.StateActive, Reason: kubeca.ReasonAdmin, ExpiresAt: read.Now.Add(time.Hour)}
	queue := &fakeRetireQueue{queue: RetireQueue{Now: read.Now, Waiting: []kubeca.RetireRequest{request}}}
	// Retiring needs no custody: the worker runs without one.
	worker := testWorker(t, store, func(context.Context) (kubeca.Custody, string, error) {
		return nil, "", kubeca.ErrMisconfigured
	})
	worker.options.Requests = queue
	return store, queue, worker, request
}

func TestRetireRequestRetiresTheRootWithItsIntermediates(t *testing.T) {
	t.Parallel()
	store, queue, worker, request := retireFixture(t)
	if ended := worker.retireRequests(context.Background(), worker.guardState(context.Background())); ended != 1 {
		t.Fatalf("ended %d requests, want 1", ended)
	}
	if len(store.changes) != 1 || len(queue.refused) != 0 {
		t.Fatalf("changes %+v, refused %v", store.changes, queue.refused)
	}
	changes := store.changes[0]
	if changes.Completes != request.ID || changes.Operator != kubeca.RetireRequestOperator(request.ID) {
		t.Fatalf("the change does not carry the request: %+v", changes)
	}
	if len(changes.Steps) != 2 || changes.Steps[1].Move.CA != request.CA ||
		changes.Steps[0].Move.To != kubeca.StateRetired || changes.Steps[0].Move.Reason != kubeca.ReasonAdmin {
		t.Fatalf("steps %+v, want the intermediate then the root retired", changes.Steps)
	}
	if len(changes.Schedules) != 1 || changes.Schedules[0].Cluster != request.Cluster {
		t.Fatalf("the cluster is not scheduled for new CAs: %+v", changes.Schedules)
	}
	if snapshot := worker.Snapshot(); snapshot.Retired != 1 || snapshot.RetireRefused != 0 {
		t.Fatalf("measurements %+v", snapshot)
	}
}

func TestRetireRequestRefusals(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		change  func(*fakeStore, *kubeca.RetireRequest)
		refusal string
	}{
		"expired": {func(_ *fakeStore, request *kubeca.RetireRequest) {
			request.ExpiresAt = request.ExpiresAt.Add(-time.Hour)
		}, kubeca.RetireRefusalExpired},
		"retired already": {func(_ *fakeStore, request *kubeca.RetireRequest) {
			request.CAState = kubeca.StateRetired
		}, kubeca.RetireRefusalGone},
		"a newer version": {func(_ *fakeStore, request *kubeca.RetireRequest) {
			request.CAVersion = 2
		}, kubeca.RetireRefusalChanged},
		"the guard on": {func(store *fakeStore, _ *kubeca.RetireRequest) {
			store.guard.Suspected = true
		}, kubeca.RetireRefusalGuard},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, queue, worker, request := retireFixture(t)
			test.change(store, &request)
			queue.queue.Waiting = []kubeca.RetireRequest{request}
			worker.retireRequests(context.Background(), worker.guardState(context.Background()))
			if queue.refused[request.ID] != test.refusal || len(store.changes) != 0 {
				t.Fatalf("refused %v, changes %+v; want %s and none", queue.refused, store.changes, test.refusal)
			}
		})
	}
}

// A compromise is retired while a restore is suspected: the safe way.
func TestRetireRequestCompromiseGoesThroughTheGuard(t *testing.T) {
	t.Parallel()
	store, queue, worker, request := retireFixture(t)
	store.guard.Suspected = true
	request.Reason = kubeca.ReasonCompromise
	queue.queue.Waiting = []kubeca.RetireRequest{request}
	worker.retireRequests(context.Background(), worker.guardState(context.Background()))
	if len(store.changes) != 1 || len(queue.refused) != 0 {
		t.Fatalf("changes %+v, refused %v", store.changes, queue.refused)
	}
}

// Requests wait, neither done nor refused, while the guard cannot be read
// (but a compromise), the Network is busy, or its read lacks the CA.
func TestRetireRequestWaits(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*fakeStore, *kubeca.RetireRequest){
		"the guard unread": func(store *fakeStore, _ *kubeca.RetireRequest) {
			store.guardErr = errors.New("database down")
		},
		"a busy Network": func(store *fakeStore, _ *kubeca.RetireRequest) { store.busy = true },
		"a CA the read lacks": func(store *fakeStore, _ *kubeca.RetireRequest) {
			store.read.Clusters[0].CAs = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			store, queue, worker, request := retireFixture(t)
			change(store, &request)
			queue.queue.Waiting = []kubeca.RetireRequest{request}
			if ended := worker.retireRequests(context.Background(), worker.guardState(context.Background())); ended != 0 {
				t.Fatalf("ended %d", ended)
			}
			if len(store.changes) != 0 || len(queue.refused) != 0 {
				t.Fatalf("changes %+v, refused %v", store.changes, queue.refused)
			}
		})
	}
	store, queue, worker, request := retireFixture(t)
	store.guardErr = errors.New("database down")
	request.Reason = kubeca.ReasonCompromise
	queue.queue.Waiting = []kubeca.RetireRequest{request}
	worker.retireRequests(context.Background(), worker.guardState(context.Background()))
	if len(store.changes) != 1 {
		t.Fatalf("a compromise waited for the guard: %+v", store.changes)
	}
}

// Requests go before the guard stops the pass.
func TestPassCarriesOutRequestsWhileGuarded(t *testing.T) {
	t.Parallel()
	store, queue, worker, request := retireFixture(t)
	store.guard.Suspected = true
	request.Reason = kubeca.ReasonCompromise
	queue.queue.Waiting = []kubeca.RetireRequest{request}
	worker.Pass(context.Background())
	if len(store.changes) != 1 || store.listed != 0 {
		t.Fatalf("changes %d, due lists %d: want the request done and no lifecycle work",
			len(store.changes), store.listed)
	}
}

type fakeMarks struct {
	regressed bool
	err       error
}

func (marks fakeMarks) Compare(context.Context, deployment.ID, kubeca.Guard) (bool, error) {
	return marks.regressed, marks.err
}

// A restore the marks reveal, though the guard read off, refuses an
// administrator's request and lets a compromise through (review d2a H1).
func TestRetireRequestsSeeARestoreTheMarksReveal(t *testing.T) {
	t.Parallel()
	store, queue, worker, request := retireFixture(t)
	worker.options.Marks = fakeMarks{regressed: true}
	compromise := request
	compromise.ID, compromise.CA = testID(t), store.read.Clusters[0].CAs[1].ID
	compromise.CAVersion, compromise.Reason = 2, kubeca.ReasonCompromise
	queue.queue.Waiting = []kubeca.RetireRequest{request, compromise}
	worker.Pass(context.Background())
	if queue.refused[request.ID] != kubeca.RetireRefusalGuard {
		t.Fatalf("the administrator's request: refused %v", queue.refused)
	}
	if len(store.changes) != 1 || store.changes[0].Completes != compromise.ID || len(store.marked) != 1 {
		t.Fatalf("changes %+v, marked %v: want the compromise only, the restore marked", store.changes, store.marked)
	}
}

// Marks that cannot be compared leave an administrator's request waiting;
// a compromise goes.
func TestRetireRequestsWaitWhileMarksAreUnknown(t *testing.T) {
	t.Parallel()
	store, queue, worker, request := retireFixture(t)
	worker.options.Marks = fakeMarks{err: errors.New("redis down")}
	worker.Pass(context.Background())
	if len(store.changes) != 0 || len(queue.refused) != 0 {
		t.Fatalf("changes %+v, refused %v", store.changes, queue.refused)
	}
	request.Reason = kubeca.ReasonCompromise
	queue.queue.Waiting = []kubeca.RetireRequest{request}
	worker.Pass(context.Background())
	if len(store.changes) != 1 {
		t.Fatalf("a compromise waited for the marks: %+v", store.changes)
	}
}

// A request past its hour by the locked clock is refused, though the
// queue listed it in time.
func TestRetireRequestExpiresUnderTheLock(t *testing.T) {
	t.Parallel()
	store, queue, worker, request := retireFixture(t)
	request.ExpiresAt = store.read.Now
	queue.queue.Now = store.read.Now.Add(-time.Minute)
	queue.queue.Waiting = []kubeca.RetireRequest{request}
	worker.retireRequests(context.Background(), guardOff)
	if queue.refused[request.ID] != kubeca.RetireRefusalExpired || len(store.changes) != 0 {
		t.Fatalf("refused %v, changes %+v", queue.refused, store.changes)
	}
}

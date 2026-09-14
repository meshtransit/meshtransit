package mapsession

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

func TestStreamServiceOwnsBoundedPresenceLifecycle(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial := snapshotFixture(t)
		advanced := advancedStreamSnapshot(t, initial)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, advanced}}
		presence := &streamPresenceStore{}
		sink := &recordingStreamSink{}
		service := newStreamServiceFixture(t, opener, presence)
		machine, request := authenticatedRequestFixture(t, initial)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, sink) }()

		synctest.Wait()
		openerCalls, openerDeadline := opener.state()
		presenceState := presence.state()
		snapshots, keepAlives := sink.state()
		if openerCalls != 1 || !openerDeadline || presenceState.claims != 1 ||
			!presenceState.sawClaimDeadline || len(snapshots) != 1 || keepAlives != 0 {
			t.Fatalf(
				"initial stream = opener(%d,%t) presence(%d,%t) sink(%d,%d)",
				openerCalls,
				openerDeadline,
				presenceState.claims,
				presenceState.sawClaimDeadline,
				len(snapshots),
				keepAlives,
			)
		}
		if presenceState.lease.NodeID() != initial.NodeID() ||
			presenceState.lease.Generation() != initial.SessionGeneration() ||
			presenceState.lease.TTL() != 9*time.Second {
			t.Fatalf("presence lease = %+v, want snapshot-bound 9s lease", presenceState.lease)
		}

		time.Sleep(3 * time.Second)
		synctest.Wait()
		presenceState = presence.state()
		if presenceState.claims != 2 {
			t.Fatalf("presence claims after renewal = %d, want 2", presenceState.claims)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		_, keepAlives = sink.state()
		if keepAlives != 1 {
			t.Fatalf("keepalives = %d, want 1", keepAlives)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		openerCalls, _ = opener.state()
		snapshots, _ = sink.state()
		if openerCalls != 2 || len(snapshots) != 2 ||
			snapshots[1].NetworkRevision() != advanced.NetworkRevision() {
			t.Fatalf("reconciled stream = opener %d snapshots %+v", openerCalls, snapshots)
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
		presenceState = presence.state()
		if presenceState.releases != 1 || !presenceState.sawReleaseDeadline {
			t.Fatalf("presence releases = (%d,%t), want one bounded release", presenceState.releases, presenceState.sawReleaseDeadline)
		}
	})
}

func TestStreamServiceReconcilesImmediatelyOnRevisionWakeup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial := snapshotFixture(t)
		advanced := advancedStreamSnapshot(t, initial)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, advanced}}
		revisions := newStreamRevisionWatcher()
		service := newStreamServiceWithRevisionsFixture(
			t,
			opener,
			&streamPresenceStore{},
			revisions,
		)
		machine, request := authenticatedRequestFixture(t, initial)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, &recordingStreamSink{}) }()

		synctest.Wait()
		wakeup, err := network.NewRevisionAdvanced(
			initial.Scope().NetworkID().String(),
			advanced.NetworkRevision(),
		)
		if err != nil {
			t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
		}
		revisions.send(t, wakeup)
		synctest.Wait()
		if calls, _ := opener.state(); calls != 2 {
			t.Fatalf("snapshot opens after wakeup = %d, want 2", calls)
		}

		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v, want context cancellation", err)
		}
		if watches, releases := revisions.state(); watches != 1 || releases != 1 {
			t.Fatalf("revision watches = (%d, %d), want one owned lifecycle", watches, releases)
		}
	})
}

func TestStreamServiceFailsClosedWhenRevisionFeedStops(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotFixture(t)
		revisions := newStreamRevisionWatcher()
		service := newStreamServiceWithRevisionsFixture(
			t,
			&streamSnapshotOpener{snapshots: []Snapshot{snapshot}},
			&streamPresenceStore{},
			revisions,
		)
		machine, request := authenticatedRequestFixture(t, snapshot)
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, &recordingStreamSink{}) }()

		synctest.Wait()
		revisions.closeUpdates()
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrStreamUnavailable) {
			t.Fatalf("Serve() error = %v, want ErrStreamUnavailable", err)
		}
	})
}

func TestStreamServiceFailsClosedWhenPresenceIsLost(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotFixture(t)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{snapshot}}
		presence := &streamPresenceStore{rejectClaim: 2}
		service := newStreamServiceFixture(t, opener, presence)
		machine, request := authenticatedRequestFixture(t, snapshot)
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, &recordingStreamSink{}) }()

		synctest.Wait()
		time.Sleep(3 * time.Second)
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrPresenceLost) {
			t.Fatalf("Serve() error = %v, want ErrPresenceLost", err)
		}
		if releases := presence.state().releases; releases != 1 {
			t.Fatalf("presence releases = %d, want one exact cleanup attempt", releases)
		}
	})
}

func TestStreamServiceRejectsConcurrentLocalOwnership(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		snapshot := snapshotFixture(t)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{snapshot}}
		presence := &streamPresenceStore{}
		service := newStreamServiceFixture(t, opener, presence)
		machine, request := authenticatedRequestFixture(t, snapshot)
		ctx, cancel := context.WithCancel(t.Context())
		firstResult := make(chan error, 1)
		go func() {
			firstResult <- service.Serve(ctx, machine, request, &recordingStreamSink{})
		}()
		synctest.Wait()

		secondErr := service.Serve(t.Context(), machine, request, &recordingStreamSink{})
		if !errors.Is(secondErr, ErrPresenceConflict) {
			t.Fatalf("concurrent Serve() error = %v, want ErrPresenceConflict", secondErr)
		}
		if claims := presence.state().claims; claims != 1 {
			t.Fatalf("Redis presence claims = %d, want only the admitted stream", claims)
		}

		cancel()
		synctest.Wait()
		if err := <-firstResult; !errors.Is(err, context.Canceled) {
			t.Fatalf("first Serve() error = %v, want context cancellation", err)
		}
	})
}

func TestStreamServiceRejectsAuthorityDiscontinuity(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial := snapshotFixture(t)
		params := initial.params()
		params.RecoveryEpoch++
		discontinuous, err := NewSnapshot(params)
		if err != nil {
			t.Fatalf("NewSnapshot() error = %v", err)
		}
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, discontinuous}}
		service := newStreamServiceFixture(t, opener, &streamPresenceStore{})
		machine, request := authenticatedRequestFixture(t, initial)
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, &recordingStreamSink{}) }()

		synctest.Wait()
		time.Sleep(5 * time.Second)
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrStreamDiscontinuity) {
			t.Fatalf("Serve() error = %v, want ErrStreamDiscontinuity", err)
		}
	})
}

func TestStreamServiceStopsAtAuthorizationExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		params := snapshotFixture(t).params()
		params.CreatedAt = time.Now().Add(-time.Hour)
		params.KeyExpiry = time.Now().Add(2 * time.Second)
		snapshot, err := NewSnapshot(params)
		if err != nil {
			t.Fatalf("NewSnapshot() error = %v", err)
		}
		service := newStreamServiceFixture(
			t,
			&streamSnapshotOpener{snapshots: []Snapshot{snapshot}},
			&streamPresenceStore{},
		)
		machine, request := authenticatedRequestFixture(t, snapshot)
		result := make(chan error, 1)
		go func() { result <- service.Serve(t.Context(), machine, request, &recordingStreamSink{}) }()

		synctest.Wait()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if err := <-result; !errors.Is(err, ErrAuthorizationExpired) {
			t.Fatalf("Serve() error = %v, want ErrAuthorizationExpired", err)
		}
	})
}

func TestNewStreamServiceRejectsUnsafeComposition(t *testing.T) {
	t.Parallel()

	options := streamOptionsFixture(t)
	revisions := newStreamRevisionWatcher()
	var nilRevisions *streamRevisionWatcher
	if _, err := NewStreamService(
		&streamSnapshotOpener{},
		&streamPresenceStore{},
		nilRevisions,
		options,
	); !errors.Is(err, ErrInvalidStreamService) {
		t.Fatalf("NewStreamService(typed nil) error = %v, want ErrInvalidStreamService", err)
	}
	if _, err := NewStreamService(nil, &streamPresenceStore{}, revisions, options); !errors.Is(
		err,
		ErrInvalidStreamService,
	) {
		t.Fatalf("NewStreamService(nil) error = %v, want ErrInvalidStreamService", err)
	}
	options.CoordinationTimeout = options.PresenceTTL / 3
	if _, err := NewStreamService(
		&streamSnapshotOpener{},
		&streamPresenceStore{},
		revisions,
		options,
	); !errors.Is(
		err,
		ErrInvalidStreamService,
	) {
		t.Fatalf("NewStreamService(unsafe timeout) error = %v, want ErrInvalidStreamService", err)
	}
}

func newStreamServiceFixture(
	t *testing.T,
	opener SnapshotOpener,
	presence PresenceStore,
) *StreamService {
	t.Helper()
	return newStreamServiceWithRevisionsFixture(
		t,
		opener,
		presence,
		newStreamRevisionWatcher(),
	)
}

func newStreamServiceWithRevisionsFixture(
	t *testing.T,
	opener SnapshotOpener,
	presence PresenceStore,
	revisions RevisionWatcher,
) *StreamService {
	t.Helper()
	service, err := NewStreamService(opener, presence, revisions, streamOptionsFixture(t))
	if err != nil {
		t.Fatalf("NewStreamService() error = %v", err)
	}
	return service
}

func streamOptionsFixture(t *testing.T) StreamOptions {
	t.Helper()
	replicaID, err := publicid.Parse("01890f00-0000-7000-8000-000000000901")
	if err != nil {
		t.Fatalf("publicid.Parse() error = %v", err)
	}
	return StreamOptions{
		ReplicaID:           replicaID,
		SnapshotTimeout:     time.Second,
		PresenceTTL:         9 * time.Second,
		CoordinationTimeout: time.Second,
		KeepAliveInterval:   4 * time.Second,
		ReconcileInterval:   5 * time.Second,
	}
}

func advancedStreamSnapshot(t *testing.T, initial Snapshot) Snapshot {
	t.Helper()
	params := initial.params()
	params.NetworkRevision++
	hostname, err := node.ParseHostname("node-2.example")
	if err != nil {
		t.Fatalf("node.ParseHostname() error = %v", err)
	}
	params.Hostname = hostname
	advanced, err := NewSnapshot(params)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	return advanced
}

type streamSnapshotOpener struct {
	mu          sync.Mutex
	snapshots   []Snapshot
	calls       int
	sawDeadline bool
}

func (opener *streamSnapshotOpener) Open(
	ctx context.Context,
	_ control.AuthenticatedMachine,
	_ Request,
) (Snapshot, error) {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	opener.calls++
	_, hasDeadline := ctx.Deadline()
	opener.sawDeadline = opener.sawDeadline || hasDeadline
	if len(opener.snapshots) == 0 {
		return Snapshot{}, errors.New("controlled snapshot failure")
	}
	index := min(opener.calls-1, len(opener.snapshots)-1)
	return opener.snapshots[index], nil
}

func (opener *streamSnapshotOpener) state() (int, bool) {
	opener.mu.Lock()
	defer opener.mu.Unlock()
	return opener.calls, opener.sawDeadline
}

type streamPresenceStore struct {
	mu                 sync.Mutex
	lease              node.PresenceLease
	claims             int
	releases           int
	rejectClaim        int
	sawClaimDeadline   bool
	sawReleaseDeadline bool
}

func (store *streamPresenceStore) ClaimPresence(
	ctx context.Context,
	lease node.PresenceLease,
) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.claims++
	store.lease = lease
	_, store.sawClaimDeadline = ctx.Deadline()
	return store.rejectClaim == 0 || store.claims != store.rejectClaim, nil
}

func (store *streamPresenceStore) ReleasePresence(
	ctx context.Context,
	lease node.PresenceLease,
) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.releases++
	store.lease = lease
	_, store.sawReleaseDeadline = ctx.Deadline()
	return true, nil
}

type streamPresenceState struct {
	lease              node.PresenceLease
	claims             int
	releases           int
	sawClaimDeadline   bool
	sawReleaseDeadline bool
}

func (store *streamPresenceStore) state() streamPresenceState {
	store.mu.Lock()
	defer store.mu.Unlock()
	return streamPresenceState{
		lease:              store.lease,
		claims:             store.claims,
		releases:           store.releases,
		sawClaimDeadline:   store.sawClaimDeadline,
		sawReleaseDeadline: store.sawReleaseDeadline,
	}
}

type recordingStreamSink struct {
	mu         sync.Mutex
	snapshots  []Snapshot
	keepAlives int
}

func (sink *recordingStreamSink) SendSnapshot(_ context.Context, snapshot Snapshot) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.snapshots = append(sink.snapshots, snapshot)
	return nil
}

func (sink *recordingStreamSink) SendKeepAlive(context.Context) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.keepAlives++
	return nil
}

func (sink *recordingStreamSink) state() ([]Snapshot, int) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return slices.Clone(sink.snapshots), sink.keepAlives
}

type streamRevisionWatcher struct {
	mu       sync.Mutex
	updates  chan network.RevisionAdvanced
	watches  int
	releases int
}

func newStreamRevisionWatcher() *streamRevisionWatcher {
	return &streamRevisionWatcher{updates: make(chan network.RevisionAdvanced, 1)}
}

func (watcher *streamRevisionWatcher) WatchNetwork(
	network.ID,
) (<-chan network.RevisionAdvanced, func(), error) {
	watcher.mu.Lock()
	watcher.watches++
	watcher.mu.Unlock()
	var releaseOnce sync.Once
	return watcher.updates, func() {
		releaseOnce.Do(func() {
			watcher.mu.Lock()
			watcher.releases++
			watcher.mu.Unlock()
		})
	}, nil
}

func (watcher *streamRevisionWatcher) send(t *testing.T, revision network.RevisionAdvanced) {
	t.Helper()
	select {
	case watcher.updates <- revision:
	case <-t.Context().Done():
		t.Fatalf("send revision wakeup: %v", t.Context().Err())
	}
}

func (watcher *streamRevisionWatcher) closeUpdates() { close(watcher.updates) }

func (watcher *streamRevisionWatcher) state() (int, int) {
	watcher.mu.Lock()
	defer watcher.mu.Unlock()
	return watcher.watches, watcher.releases
}

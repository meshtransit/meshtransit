package mapsession

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"sync"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/network"
)

type streamWakeup struct {
	revision     network.RevisionAdvanced
	connectivity ConnectivityChanged
	reconcile    bool
}

// One owned multiplexer per stream, regardless of the bounded Network count.
// A full buffer coalesces to a complete reread; notifications grant no authority.
type streamWatch struct {
	scopes   []network.Scope
	updates  chan streamWakeup
	failure  chan error
	cancel   context.CancelFunc
	done     chan struct{}
	releases []func()
	once     sync.Once
}

func (service *StreamService) watchSnapshot(ctx context.Context, snapshot Snapshot) (*streamWatch, error) {
	scopes := append([]network.Scope{snapshot.Scope()}, snapshot.SharingScopes()...)
	watchContext, cancel := context.WithCancel(ctx)
	watch := &streamWatch{scopes: scopes, updates: make(chan streamWakeup, 1), failure: make(chan error, 1), cancel: cancel, done: make(chan struct{})}
	cases := []reflect.SelectCase{{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(watchContext.Done())}}
	expected := make([]network.ID, 1, 1+2*len(scopes))
	for _, scope := range scopes {
		revisions, release, err := service.revisions.WatchNetwork(scope.NetworkID())
		if release != nil {
			watch.releases = append(watch.releases, release)
		}
		if err != nil || revisions == nil || release == nil {
			cancel()
			for _, stop := range watch.releases {
				stop()
			}
			return nil, errors.Join(ErrStreamUnavailable, err)
		}
		connectivity, stop, err := service.connectivity.WatchNetwork(scope.NetworkID())
		if stop != nil {
			watch.releases = append(watch.releases, stop)
		}
		if err != nil || connectivity == nil || stop == nil {
			cancel()
			for _, release := range watch.releases {
				release()
			}
			return nil, errors.Join(ErrStreamUnavailable, err)
		}
		cases = append(cases, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(revisions)}, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(connectivity)})
		expected = append(expected, scope.NetworkID(), scope.NetworkID())
	}
	go watch.forward(cases, expected)
	return watch, nil
}

func (watch *streamWatch) forward(cases []reflect.SelectCase, expected []network.ID) {
	defer close(watch.done)
	for {
		index, value, open := reflect.Select(cases)
		if index == 0 {
			return
		}
		if !open {
			watch.failure <- ErrStreamUnavailable
			return
		}
		wake := streamWakeup{}
		valid := false
		if index%2 == 1 {
			revision, ok := value.Interface().(network.RevisionAdvanced)
			valid = ok && revision.IsValid() && revision.NetworkID() == expected[index]
			wake.revision = revision
		} else {
			change, ok := value.Interface().(ConnectivityChanged)
			valid = ok && change.IsValid() && change.NetworkID() == expected[index]
			wake.connectivity = change
		}
		if !valid {
			watch.failure <- ErrStreamDiscontinuity
			return
		}
		select {
		case watch.updates <- wake:
		default:
			select {
			case <-watch.updates:
			default:
			}
			select {
			case watch.updates <- streamWakeup{reconcile: true}:
			default:
			}
		}
	}
}

func (watch *streamWatch) close() {
	watch.once.Do(func() {
		watch.cancel()
		<-watch.done
		for _, release := range watch.releases {
			release()
		}
	})
}

// Subscribe before the final authoritative read. Sharing scope churn is bounded;
// no initial packet map is released until every returned scope is subscribed.
func (service *StreamService) watchInitialSnapshot(ctx context.Context, machine control.AuthenticatedMachine, request Request, current Snapshot) (Snapshot, *streamWatch, error) {
	for attempt := 0; attempt < 4; attempt++ {
		watch, err := service.watchSnapshot(ctx, current)
		if err != nil {
			return Snapshot{}, nil, err
		}
		if len(current.SharingScopes()) == 0 {
			return current, watch, nil
		}
		next, err := service.openSnapshot(ctx, machine, request)
		if err != nil {
			watch.close()
			return Snapshot{}, nil, errors.Join(ErrStreamUnavailable, err)
		}
		if !streamCanAdvance(current, next) {
			watch.close()
			return Snapshot{}, nil, ErrStreamDiscontinuity
		}
		scopes := append([]network.Scope{next.Scope()}, next.SharingScopes()...)
		if slices.Equal(scopes, watch.scopes) {
			select {
			case err := <-watch.failure:
				watch.close()
				return Snapshot{}, nil, err
			default:
			}
			if err := ctx.Err(); err != nil {
				watch.close()
				return Snapshot{}, nil, err
			}
			return next, watch, nil
		}
		watch.close()
		current = next
	}
	return Snapshot{}, nil, ErrStreamDiscontinuity
}

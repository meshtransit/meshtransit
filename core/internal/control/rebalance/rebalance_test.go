package rebalance

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"testing/synctest"
	"time"
)

func testOptions() Options {
	return Options{ReplicaID: "a", Interval: 10 * time.Second, Shed: true, Tolerance: 0.1, MinExcess: 10,
		MaxShedFraction: 0.05, ReconnectWindow: 10 * time.Second, Logger: slog.New(slog.DiscardHandler)}
}

func loads(counts ...int) []ReplicaLoad {
	values := make([]ReplicaLoad, len(counts))
	for index, count := range counts {
		values[index] = ReplicaLoad{ReplicaID: string(rune('a' + index)), Sessions: count}
	}
	return values
}

func TestPlanShedsOnlyClearExcess(t *testing.T) {
	t.Parallel()
	options := testOptions()
	for name, test := range map[string]struct {
		own   int
		loads []ReplicaLoad
		want  int
	}{
		"alone never sheds":           {own: 10_000, loads: loads(10_000), want: 0},
		"balanced":                    {own: 1000, loads: loads(1000, 1000), want: 0},
		"within tolerance":            {own: 1090, loads: loads(1090, 910), want: 0},
		"new replica takes a share":   {own: 2000, loads: loads(2000, 0), want: 100},       // 5% of 2000
		"bounded per step":            {own: 1200, loads: loads(1200, 900, 900), want: 60}, // fair 1000, 5% of 1200
		"small numbers use min":       {own: 15, loads: loads(15, 1), want: 0},             // fair 8, allowed 18
		"at least one when over":      {own: 40, loads: loads(40, 0), want: 2},             // 5% of 40
		"one session still sheds one": {own: 30, loads: loads(30, 0, 0), want: 1},
	} {
		if got := Plan(test.own, test.loads, options); got != test.want {
			t.Errorf("%s: Plan() = %d, want %d", name, got, test.want)
		}
	}
}

type registryFixture struct {
	mu        sync.Mutex
	others    []ReplicaLoad
	published []int
	withdrawn bool
	fail      bool
}

func (registry *registryFixture) PublishLoad(_ context.Context, id string, sessions int, ttl time.Duration) ([]ReplicaLoad, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.fail {
		return nil, errors.New("redis down")
	}
	if ttl != 30*time.Second {
		return nil, errors.New("unexpected ttl")
	}
	registry.published = append(registry.published, sessions)
	return append([]ReplicaLoad{{ReplicaID: id, Sessions: sessions}}, registry.others...), nil
}

func (registry *registryFixture) WithdrawLoad(context.Context, string) error {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	registry.withdrawn = true
	return nil
}

func (registry *registryFixture) Loads(context.Context) ([]ReplicaLoad, error) {
	registry.mu.Lock()
	defer registry.mu.Unlock()
	if registry.fail {
		return nil, errors.New("redis down")
	}
	return append([]ReplicaLoad{{ReplicaID: "a", Sessions: 7}}, registry.others...), nil
}

type poolFixture struct {
	mu       sync.Mutex
	sessions int
	sheds    []int
	moveTo   *registryFixture // shed sessions reconnect to its first other replica
}

func (pool *poolFixture) Sessions() int {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.sessions
}

func (pool *poolFixture) Shed(_ context.Context, count int, _ time.Duration) int {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	pool.sheds = append(pool.sheds, count)
	pool.sessions -= count
	if pool.moveTo != nil {
		pool.moveTo.mu.Lock()
		pool.moveTo.others[0].Sessions += count
		pool.moveTo.mu.Unlock()
	}
	return count
}

func TestBalancerConvergesTowardTheFairShare(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		registry := &registryFixture{others: []ReplicaLoad{{ReplicaID: "b"}}}
		pool := &poolFixture{sessions: 1000, moveTo: registry}
		balancer, err := New(registry, pool, testOptions())
		if err != nil {
			t.Fatal(err)
		}
		if err := balancer.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = balancer.Shutdown(context.Background()) }()
		time.Sleep(10 * time.Minute)
		synctest.Wait()
		if got := pool.Sessions(); got > 560 || got < 490 {
			t.Fatalf("sessions after rebalancing = %d, want near the fair share 500", got)
		}
		for _, shed := range pool.sheds {
			if shed > 50 {
				t.Fatalf("one step shed %d sessions, over 5%% of 1000", shed)
			}
		}
		if err := balancer.Shutdown(t.Context()); err != nil {
			t.Fatal(err)
		}
		if !registry.withdrawn {
			t.Fatal("Shutdown() did not withdraw the replica")
		}
	})
}

func TestBalancerPublishesWithoutSheddingWhenSwitchedOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		registry := &registryFixture{others: []ReplicaLoad{{ReplicaID: "b"}}}
		pool := &poolFixture{sessions: 1000}
		options := testOptions()
		options.Shed = false
		balancer, err := New(registry, pool, options)
		if err != nil {
			t.Fatal(err)
		}
		_ = balancer.Start(t.Context())
		time.Sleep(time.Minute)
		synctest.Wait()
		if len(pool.sheds) != 0 || len(registry.published) < 4 {
			t.Fatalf("sheds = %v, publications = %d", pool.sheds, len(registry.published))
		}
		_ = balancer.Shutdown(t.Context())
	})
}

func TestScaleHandlerReportsTheClusterTotal(t *testing.T) {
	t.Parallel()
	registry := &registryFixture{others: []ReplicaLoad{{ReplicaID: "b", Sessions: 5}}}
	recorder := httptest.NewRecorder()
	ScaleHandler(registry).ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, ScalePath, nil))
	if recorder.Code != http.StatusOK || recorder.Body.String() != "{\"sessions\":12,\"replicas\":2}\n" {
		t.Fatalf("response = %d %q", recorder.Code, recorder.Body.String())
	}
	registry.fail = true
	recorder = httptest.NewRecorder()
	ScaleHandler(registry).ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, ScalePath, nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable registry answered %d", recorder.Code)
	}
}

func TestNewRejectsUnsafeOptions(t *testing.T) {
	t.Parallel()
	options := testOptions()
	options.MaxShedFraction = 0.9
	if _, err := New(&registryFixture{}, &poolFixture{}, options); !errors.Is(err, ErrInvalidBalancer) {
		t.Fatalf("New() error = %v", err)
	}
}

func TestStableTotalIgnoresRampsAndReconnectWaves(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		previous, current int
		want              bool
	}{
		"first step":     {0, 1000, false},
		"steady":         {1000, 1010, true},
		"small cluster":  {10, 40, true}, // within 32 sessions
		"ramp":           {1000, 1200, false},
		"reconnect wave": {2000, 1500, false},
		"just within 5%": {10000, 10500, true},
		"just beyond 5%": {10000, 10600, false},
	} {
		if got := stableTotal(test.previous, test.current); got != test.want {
			t.Errorf("%s: stableTotal(%d, %d) = %t", name, test.previous, test.current, got)
		}
	}
}

func TestBalancerWaitsWhileTheTotalRamps(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		registry := &registryFixture{others: []ReplicaLoad{{ReplicaID: "b"}}}
		pool := &poolFixture{sessions: 600}
		balancer, err := New(registry, pool, testOptions())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = balancer.Shutdown(context.Background()) }()
		_ = balancer.Start(t.Context())
		// Both replicas ramp up together, but the other one's published load
		// lags a step behind, so this replica looks over its share. The
		// total grows faster than 5% per interval: nothing is shed.
		for range 12 {
			pool.mu.Lock()
			pool.sessions += 300
			own := pool.sessions
			pool.mu.Unlock()
			registry.mu.Lock()
			registry.others[0].Sessions = own - 600
			registry.mu.Unlock()
			time.Sleep(5 * time.Second)
			synctest.Wait()
		}
		if len(pool.sheds) != 0 {
			t.Fatalf("shed %v during a ramp", pool.sheds)
		}
	})
}

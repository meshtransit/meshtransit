package relay

import (
	"errors"
	"testing"
	"time"
)

func TestHomeSelectorReconcile(t *testing.T) {
	t.Parallel()

	selector := NewHomeSelector()
	result, err := selector.Reconcile(2, []int{3, 2, 1})
	if err != nil || result.RegionID != 2 || !result.Changed {
		t.Fatalf("Reconcile() = %#v, %v", result, err)
	}
	result, err = selector.Reconcile(2, []int{3, 2, 1})
	if err != nil || result.RegionID != 2 || result.Changed {
		t.Fatalf("stable Reconcile() = %#v, %v", result, err)
	}
	result, err = selector.Reconcile(3, []int{3, 2, 1})
	if err != nil || result.RegionID != 3 || !result.Changed {
		t.Fatalf("control change Reconcile() = %#v, %v", result, err)
	}
	result, err = selector.Reconcile(3, []int{2, 1})
	if err != nil || result.RegionID != 1 || !result.Changed {
		t.Fatalf("removed region Reconcile() = %#v, %v", result, err)
	}
}

func TestHomeSelectorUsesMaterialLatencyImprovement(t *testing.T) {
	t.Parallel()

	selector := NewHomeSelector()
	now := time.Now()
	if _, err := selector.Reconcile(1, []int{1, 2}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	result, err := selector.Observe(now, []RegionLatency{
		{RegionID: 1, Latency: 50 * time.Millisecond},
		{RegionID: 2, Latency: 42 * time.Millisecond},
	}, healthyRelaySnapshot(now, 1, 1, 2))
	if err != nil || result.RegionID != 1 || result.Changed {
		t.Fatalf("small gain Observe() = %#v, %v", result, err)
	}
	result, err = selector.Observe(now.Add(time.Second), []RegionLatency{
		{RegionID: 1, Latency: 70 * time.Millisecond},
		{RegionID: 2, Latency: 20 * time.Millisecond},
	}, healthyRelaySnapshot(now.Add(time.Second), 1, 1, 2))
	if err != nil || result.RegionID != 2 || !result.Changed {
		t.Fatalf("material gain Observe() = %#v, %v", result, err)
	}
	result, err = selector.Reconcile(1, []int{1, 2})
	if err != nil || result.RegionID != 2 || result.Changed {
		t.Fatalf("unacknowledged Reconcile() = %#v, %v", result, err)
	}
	result, err = selector.Reconcile(2, []int{1, 2})
	if err != nil || result.RegionID != 2 || result.Changed {
		t.Fatalf("acknowledged Reconcile() = %#v, %v", result, err)
	}
}

func TestHomeSelectorDoesNotBlendExpiredLatency(t *testing.T) {
	t.Parallel()

	selector := NewHomeSelector()
	now := time.Now()
	if _, err := selector.Reconcile(1, []int{1, 2}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if _, err := selector.Observe(now, []RegionLatency{
		{RegionID: 1, Latency: 20 * time.Millisecond},
		{RegionID: 2, Latency: 200 * time.Millisecond},
	}, healthyRelaySnapshot(now, 1, 1, 2)); err != nil {
		t.Fatalf("Observe() initial error = %v", err)
	}
	result, err := selector.Observe(
		now.Add(selectionLatencyRetention),
		[]RegionLatency{
			{RegionID: 1, Latency: 200 * time.Millisecond},
			{RegionID: 2, Latency: 20 * time.Millisecond},
		},
		healthyRelaySnapshot(now.Add(selectionLatencyRetention), 1, 1, 2),
	)
	if err != nil || result.RegionID != 2 || !result.Changed {
		t.Fatalf("Observe() after expiry = %#v, %v", result, err)
	}
}

func TestHomeSelectorRequiresRepeatedReachabilityMiss(t *testing.T) {
	t.Parallel()

	selector := NewHomeSelector()
	now := time.Now()
	if _, err := selector.Reconcile(1, []int{1, 2}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	for round := 1; round <= 2; round++ {
		result, err := selector.Observe(now.Add(time.Duration(round)*time.Second), []RegionLatency{{
			RegionID: 2,
			Latency:  20 * time.Millisecond,
		}}, healthyRelaySnapshot(now.Add(time.Duration(round)*time.Second), 1, 2))
		if err != nil {
			t.Fatalf("Observe() round %d error = %v", round, err)
		}
		if round == 1 && (result.RegionID != 1 || result.Changed) {
			t.Fatalf("first miss Observe() = %#v", result)
		}
		if round == 2 && (result.RegionID != 2 || !result.Changed) {
			t.Fatalf("second miss Observe() = %#v", result)
		}
	}
}

func TestHomeSelectorDoesNotFailOverOnEmptyRound(t *testing.T) {
	t.Parallel()

	selector := NewHomeSelector()
	now := time.Now()
	if _, err := selector.Reconcile(1, []int{1, 2}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	for round := 1; round <= missesBeforeRelayFailover; round++ {
		result, err := selector.Observe(
			now.Add(time.Duration(round)*time.Second),
			nil,
			healthyRelaySnapshot(now.Add(time.Duration(round)*time.Second), 1, 1),
		)
		if err != nil || result.RegionID != 1 || result.Changed {
			t.Fatalf("empty Observe() round %d = %#v, %v", round, result, err)
		}
	}
}

func TestHomeSelectorRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	selector := NewHomeSelector()
	now := time.Now()
	if _, err := selector.Reconcile(0, []int{1, 1}); !errors.Is(err, errInvalidSelection) {
		t.Fatalf("Reconcile() error = %v, want invalid input", err)
	}
	if _, err := selector.Reconcile(1, []int{1}); err != nil {
		t.Fatalf("Reconcile() valid error = %v", err)
	}
	if _, err := selector.Observe(now, []RegionLatency{{
		RegionID: 2,
		Latency:  time.Millisecond,
	}}, HealthSnapshot{}); !errors.Is(err, errInvalidSelection) {
		t.Fatalf("Observe() error = %v, want invalid input", err)
	}
}

func TestHomeSelectorPreparesReplacementBeforeSwitch(t *testing.T) {
	t.Parallel()

	selector := NewHomeSelector()
	now := time.Now()
	if _, err := selector.Reconcile(1, []int{1, 2}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	samples := []RegionLatency{
		{RegionID: 1, Latency: 100 * time.Millisecond},
		{RegionID: 2, Latency: 20 * time.Millisecond},
	}
	result, err := selector.Observe(now, samples, healthyRelaySnapshot(now, 1, 1))
	if err != nil || result.RegionID != 1 || result.Changed || result.PreparationRegionID != 2 {
		t.Fatalf("unprepared Observe() = %#v, %v", result, err)
	}
	now = now.Add(time.Second)
	result, err = selector.Observe(now, samples, healthyRelaySnapshot(now, 1, 1, 2))
	if err != nil || result.RegionID != 2 || !result.Changed || result.PreparationRegionID != 0 {
		t.Fatalf("prepared Observe() = %#v, %v", result, err)
	}
}

func TestHomeSelectorRetainsPreparedCandidateAcrossProbeBatches(t *testing.T) {
	t.Parallel()

	selector := NewHomeSelector()
	now := time.Now()
	if _, err := selector.Reconcile(1, []int{1, 2, 3}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	result, err := selector.Observe(now, []RegionLatency{
		{RegionID: 1, Latency: 100 * time.Millisecond},
		{RegionID: 2, Latency: 20 * time.Millisecond},
	}, healthyRelaySnapshot(now, 1, 1))
	if err != nil || result.RegionID != 1 || result.PreparationRegionID != 2 {
		t.Fatalf("first batch Observe() = %#v, %v", result, err)
	}
	now = now.Add(time.Second)
	result, err = selector.Observe(now, []RegionLatency{
		{RegionID: 1, Latency: 100 * time.Millisecond},
		{RegionID: 3, Latency: 40 * time.Millisecond},
	}, healthyRelaySnapshot(now, 1, 1, 2))
	if err != nil || result.RegionID != 2 || !result.Changed ||
		result.PreparationRegionID != 0 {
		t.Fatalf("rotated batch Observe() = %#v, %v", result, err)
	}
}

func TestHomeSelectorKeepsRecentlyActiveHomeWithoutSTUN(t *testing.T) {
	t.Parallel()

	selector := NewHomeSelector()
	now := time.Now()
	if _, err := selector.Reconcile(1, []int{1, 2}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	for round := 1; round <= missesBeforeRelayFailover+1; round++ {
		observedAt := now.Add(time.Duration(round) * time.Second)
		result, err := selector.Observe(observedAt, []RegionLatency{{
			RegionID: 2,
			Latency:  20 * time.Millisecond,
		}}, healthyRelaySnapshot(observedAt, 1, 1, 2))
		if err != nil || result.RegionID != 1 || result.Changed ||
			result.PreparationRegionID != 0 {
			t.Fatalf("active-home Observe() round %d = %#v, %v", round, result, err)
		}
	}
}

func TestHomeSelectorFailsOverWhenCurrentRelayFails(t *testing.T) {
	t.Parallel()

	selector := NewHomeSelector()
	now := time.Now()
	if _, err := selector.Reconcile(1, []int{1, 2}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	samples := []RegionLatency{
		{RegionID: 1, Latency: 10 * time.Millisecond},
		{RegionID: 2, Latency: 30 * time.Millisecond},
	}
	for round := 1; round <= missesBeforeRelayFailover; round++ {
		observedAt := now.Add(time.Duration(round) * time.Second)
		health := healthyRelaySnapshot(observedAt, 1, 2)
		health.Regions = append(health.Regions, RegionHealth{
			RegionID:            1,
			LastFailure:         observedAt,
			ConsecutiveFailures: 1,
		})
		result, err := selector.Observe(observedAt, samples, health)
		if err != nil {
			t.Fatalf("Observe() round %d error = %v", round, err)
		}
		if round == 1 && (result.RegionID != 1 || result.Changed) {
			t.Fatalf("first failed-health Observe() = %#v", result)
		}
		if round == 2 && (result.RegionID != 2 || !result.Changed) {
			t.Fatalf("second failed-health Observe() = %#v", result)
		}
	}
}

func TestHomeSelectorPreparesStaleReplacement(t *testing.T) {
	t.Parallel()

	selector := NewHomeSelector()
	now := time.Now()
	if _, err := selector.Reconcile(1, []int{1, 2}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	health := healthyRelaySnapshot(now, 1, 1, 2)
	health.Regions[1].LastConnected = now.Add(-relayActivityRetention - 2*time.Second)
	health.Regions[1].LastActivity = now.Add(-relayActivityRetention - time.Second)
	result, err := selector.Observe(now, []RegionLatency{
		{RegionID: 1, Latency: 100 * time.Millisecond},
		{RegionID: 2, Latency: 20 * time.Millisecond},
	}, health)
	if err != nil || result.RegionID != 1 || result.Changed ||
		result.PreparationRegionID != 2 {
		t.Fatalf("Observe() = %#v, %v", result, err)
	}
}

func TestHomeSelectorRejectsInvalidHealth(t *testing.T) {
	t.Parallel()

	selector := NewHomeSelector()
	now := time.Now()
	if _, err := selector.Reconcile(1, []int{1, 2}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	tests := []struct {
		name   string
		health HealthSnapshot
	}{
		{
			name: "duplicate region",
			health: HealthSnapshot{
				Available:  true,
				HomeRegion: 1,
				Regions: []RegionHealth{
					{RegionID: 1},
					{RegionID: 1},
				},
			},
		},
		{
			name: "future activity",
			health: HealthSnapshot{
				Available:  true,
				HomeRegion: 1,
				Regions: []RegionHealth{{
					RegionID:     1,
					LastActivity: now.Add(time.Second),
				}},
			},
		},
		{
			name: "failure without timestamp",
			health: HealthSnapshot{
				Available:  true,
				HomeRegion: 1,
				Regions: []RegionHealth{{
					RegionID:            1,
					ConsecutiveFailures: 1,
				}},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := selector.Observe(now, []RegionLatency{{
				RegionID: 1,
				Latency:  time.Millisecond,
			}}, test.health)
			if !errors.Is(err, errInvalidSelection) {
				t.Fatalf("Observe() error = %v, want invalid input", err)
			}
		})
	}
}

func healthyRelaySnapshot(now time.Time, homeRegion int, connectedRegions ...int) HealthSnapshot {
	regions := make([]RegionHealth, 0, len(connectedRegions))
	for _, regionID := range connectedRegions {
		regions = append(regions, RegionHealth{
			RegionID:      regionID,
			Connected:     true,
			LastConnected: now.Add(-time.Second),
			LastActivity:  now,
		})
	}

	return HealthSnapshot{
		Available:  true,
		HomeRegion: homeRegion,
		Regions:    regions,
	}
}

func TestHomeSelectorReset(t *testing.T) {
	t.Parallel()

	selector := NewHomeSelector()
	if _, err := selector.Reconcile(1, []int{1}); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if result := selector.Reset(); result.RegionID != 0 || !result.Changed {
		t.Fatalf("Reset() = %#v", result)
	}
}

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
	})
	if err != nil || result.RegionID != 1 || result.Changed {
		t.Fatalf("small gain Observe() = %#v, %v", result, err)
	}
	result, err = selector.Observe(now.Add(time.Second), []RegionLatency{
		{RegionID: 1, Latency: 70 * time.Millisecond},
		{RegionID: 2, Latency: 20 * time.Millisecond},
	})
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
	}); err != nil {
		t.Fatalf("Observe() initial error = %v", err)
	}
	result, err := selector.Observe(
		now.Add(selectionLatencyRetention),
		[]RegionLatency{
			{RegionID: 1, Latency: 200 * time.Millisecond},
			{RegionID: 2, Latency: 20 * time.Millisecond},
		},
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
		}})
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
	}}); !errors.Is(err, errInvalidSelection) {
		t.Fatalf("Observe() error = %v, want invalid input", err)
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

package revisionworker

import (
	"sync"
	"testing"
	"time"
)

func TestTelemetryRecordsBoundedWorkerOutcomesConcurrently(t *testing.T) {
	t.Parallel()

	telemetry := NewTelemetry()
	backlog, err := NewBacklog(8, 3*time.Second)
	if err != nil {
		t.Fatalf("NewBacklog() error = %v", err)
	}
	telemetry.recordBacklog(backlog)

	const repetitions = 100
	var workers sync.WaitGroup
	workers.Add(3)
	go func() {
		defer workers.Done()
		for range repetitions {
			telemetry.recordClaim(2, nil)
			telemetry.recordDelivery(deliveryDelivered)
		}
	}()
	go func() {
		defer workers.Done()
		for range repetitions {
			telemetry.recordBacklogError()
			telemetry.recordClaim(0, ErrInvalidClaimBatch)
			telemetry.recordDelivery(deliveryDeferred)
		}
	}()
	go func() {
		defer workers.Done()
		for range repetitions {
			telemetry.recordDelivery(deliveryFailed)
		}
	}()
	workers.Wait()

	snapshot := telemetry.Snapshot()
	if snapshot.ReadyBacklogEvents != 8 || snapshot.OldestReadyEventAge != 3*time.Second {
		t.Fatalf(
			"backlog snapshot = (%d, %s), want (8, 3s)",
			snapshot.ReadyBacklogEvents,
			snapshot.OldestReadyEventAge,
		)
	}
	if snapshot.BacklogSuccessTotal != 1 || snapshot.BacklogErrorTotal != repetitions ||
		snapshot.ClaimSuccessTotal != repetitions || snapshot.ClaimErrorTotal != repetitions ||
		snapshot.ClaimedEventsTotal != 2*repetitions || snapshot.DeliveredTotal != repetitions ||
		snapshot.DeferredTotal != repetitions || snapshot.FailedTotal != repetitions {
		t.Fatalf("unexpected telemetry snapshot: %+v", snapshot)
	}
}

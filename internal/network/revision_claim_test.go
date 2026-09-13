package network

import (
	"errors"
	"testing"
	"time"
)

const testClaimID = "550e8400-e29b-41d4-a716-446655440000"

func TestNewRevisionClaim(t *testing.T) {
	t.Parallel()

	claimedAt := time.Date(2026, 9, 13, 2, 0, 0, 0, time.UTC)
	claim, err := NewRevisionClaim(
		91,
		101,
		201,
		42,
		testClaimID,
		"worker-1",
		3,
		claimedAt,
	)
	if err != nil {
		t.Fatalf("NewRevisionClaim() error = %v", err)
	}
	if claim.EventID() != 91 || claim.WorkspaceID() != 101 || claim.NetworkID() != 201 ||
		claim.RecordedRevision() != 42 || claim.Token() != testClaimID ||
		claim.WorkerID() != "worker-1" || claim.Attempt() != 3 || !claim.ClaimedAt().Equal(claimedAt) {
		t.Fatalf("NewRevisionClaim() = %+v, want complete immutable claim", claim)
	}
}

func TestNewRevisionClaimRejectsInvalidState(t *testing.T) {
	t.Parallel()

	validTime := time.Date(2026, 9, 13, 2, 0, 0, 0, time.UTC)
	tests := []struct {
		name             string
		eventID          int64
		workspaceID      int64
		networkID        int64
		recordedRevision int64
		claimID          string
		workerID         string
		attempt          int
		claimedAt        time.Time
	}{
		{name: "zero event", workspaceID: 101, networkID: 201, recordedRevision: 42, claimID: testClaimID, workerID: "worker-1", attempt: 1, claimedAt: validTime},
		{name: "zero workspace", eventID: 91, networkID: 201, recordedRevision: 42, claimID: testClaimID, workerID: "worker-1", attempt: 1, claimedAt: validTime},
		{name: "zero network", eventID: 91, workspaceID: 101, recordedRevision: 42, claimID: testClaimID, workerID: "worker-1", attempt: 1, claimedAt: validTime},
		{name: "zero revision", eventID: 91, workspaceID: 101, networkID: 201, claimID: testClaimID, workerID: "worker-1", attempt: 1, claimedAt: validTime},
		{name: "invalid claim", eventID: 91, workspaceID: 101, networkID: 201, recordedRevision: 42, claimID: "invalid", workerID: "worker-1", attempt: 1, claimedAt: validTime},
		{name: "blank worker", eventID: 91, workspaceID: 101, networkID: 201, recordedRevision: 42, claimID: testClaimID, workerID: " ", attempt: 1, claimedAt: validTime},
		{name: "zero attempt", eventID: 91, workspaceID: 101, networkID: 201, recordedRevision: 42, claimID: testClaimID, workerID: "worker-1", claimedAt: validTime},
		{name: "zero claimed time", eventID: 91, workspaceID: 101, networkID: 201, recordedRevision: 42, claimID: testClaimID, workerID: "worker-1", attempt: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewRevisionClaim(
				test.eventID,
				test.workspaceID,
				test.networkID,
				test.recordedRevision,
				test.claimID,
				test.workerID,
				test.attempt,
				test.claimedAt,
			)
			if !errors.Is(err, ErrInvalidRevisionClaim) {
				t.Fatalf("NewRevisionClaim() error = %v, want ErrInvalidRevisionClaim", err)
			}
		})
	}
}

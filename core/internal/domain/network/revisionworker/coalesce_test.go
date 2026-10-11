package revisionworker

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/platform/observability"
)

func claimFor(t *testing.T, eventID, networkID, revision int64, token string) network.RevisionClaim {
	t.Helper()
	claim, err := network.NewRevisionClaim(eventID, 2, networkID, revision, token, "revision-worker", 1, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	return claim
}

// Streams read up to the newest revision on any wakeup, so a batch that
// holds several revisions of one Network needs a single wakeup carrying the
// newest; every claim is still marked delivered.
func TestDispatchOncePublishesOneWakeupPerNetwork(t *testing.T) {
	t.Parallel()
	const first, second = "01890f5e-7b9a-7123-8abc-1234567890ab", "01890f5e-7b9a-7123-8abc-1234567890cd"
	claims := []network.RevisionClaim{
		claimFor(t, 1, 3, 3, first), claimFor(t, 2, 3, 5, first), claimFor(t, 3, 4, 9, second), claimFor(t, 4, 3, 4, first),
	}
	revisions := map[int64]network.RevisionAdvanced{}
	for _, claim := range claims {
		networkID := first
		if claim.NetworkID() == 4 {
			networkID = second
		}
		revision, err := network.NewRevisionAdvanced(networkID, claim.RecordedRevision())
		if err != nil {
			t.Fatal(err)
		}
		revisions[claim.EventID()] = revision
	}
	var published []network.RevisionAdvanced
	marked := map[int64]bool{}
	outbox := &fakeOutbox{
		claim: func(context.Context, string, int, time.Duration) ([]network.RevisionClaim, error) { return claims, nil },
		load: func(_ context.Context, claim network.RevisionClaim) (network.RevisionAdvanced, error) {
			return revisions[claim.EventID()], nil
		},
		mark: func(_ context.Context, claim network.RevisionClaim) error {
			marked[claim.EventID()] = true
			return nil
		},
	}
	publisher := &fakePublisher{publish: func(_ context.Context, revision network.RevisionAdvanced) error {
		published = append(published, revision)
		return nil
	}}
	logger, err := observability.NewLogger(io.Discard, slog.LevelDebug)
	if err != nil {
		t.Fatal(err)
	}
	options := replaceBatchSize(testOptions(), 8)
	options.Lease = 30 * time.Second // the batch's I/O budget must fit the lease
	dispatcher, err := New(options, outbox, publisher, NewTelemetry(), logger)
	if err != nil {
		t.Fatal(err)
	}
	if claimed, err := dispatcher.dispatchOnce(t.Context()); err != nil || claimed != len(claims) {
		t.Fatalf("dispatchOnce() = %d, %v", claimed, err)
	}
	if len(published) != 2 {
		t.Fatalf("published %d wakeups, want one per Network", len(published))
	}
	newest := map[string]int64{}
	for _, revision := range published {
		newest[revision.NetworkPublicID()] = revision.Number()
	}
	if newest[first] != 5 || newest[second] != 9 {
		t.Fatalf("published %v, want the newest revision of each Network", newest)
	}
	if len(marked) != len(claims) {
		t.Fatalf("marked %d claims delivered, want %d", len(marked), len(claims))
	}
}

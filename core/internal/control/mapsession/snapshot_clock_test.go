package mapsession

import (
	"testing"
	"time"
)

// TestSnapshotMeasuresDeadlinesOnTheDatabaseClock checks that key and
// projection deadlines, which the database clock set, are measured from the
// snapshot's database read time and this host's monotonic clock, whatever
// this host's wall clock says.
func TestSnapshotMeasuresDeadlinesOnTheDatabaseClock(t *testing.T) {
	t.Parallel()
	base := snapshotFixture(t)

	// This host's wall clock is an hour behind the database: by the host
	// the deadline is an hour away, by the database it has passed.
	deadline := time.Now().Add(time.Hour)
	behind := base
	behind.databaseReadAt, behind.readAtLocal = deadline.Add(time.Second), time.Now()
	if !behind.deadlinePassed(deadline) {
		t.Fatalf("a deadline past on the database clock is %s away", behind.untilDeadline(deadline))
	}

	// This host's wall clock is an hour ahead: by the host the deadline
	// passed half an hour ago, by the database it is half an hour away.
	deadline = time.Now().Add(-30 * time.Minute)
	ahead := base
	ahead.databaseReadAt, ahead.readAtLocal = deadline.Add(-30*time.Minute), time.Now()
	if ahead.deadlinePassed(deadline) || ahead.untilDeadline(deadline) < 29*time.Minute {
		t.Fatalf("a deadline half an hour away on the database clock is %s away", ahead.untilDeadline(deadline))
	}

	// Time elapsed since the read counts on this host's monotonic clock.
	elapsed := base
	elapsed.databaseReadAt, elapsed.readAtLocal = deadline.Add(-time.Minute), time.Now().Add(-2*time.Minute)
	if !elapsed.deadlinePassed(deadline) {
		t.Fatal("a deadline one minute after a read two minutes ago has not passed")
	}

	// Without a database read time the host clock decides.
	unknown := base
	unknown.databaseReadAt = time.Time{}
	if unknown.deadlinePassed(time.Now().Add(time.Hour)) || !unknown.deadlinePassed(time.Now().Add(-time.Second)) {
		t.Fatal("without a database read time the host clock does not decide")
	}
}

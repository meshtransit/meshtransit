package mapsession

import (
	"testing"
	"time"
)

// TestInventoryMeasuresNowOnTheDatabaseClock checks that an inventory's
// notion of now is its read's database time plus the time elapsed since on
// this host's monotonic clock, so a host wall clock far from the database's
// does not move it.
func TestInventoryMeasuresNowOnTheDatabaseClock(t *testing.T) {
	t.Parallel()
	readAt := time.Date(2001, 2, 3, 4, 5, 6, 0, time.UTC)
	cached := cachedInventory{readAt: readAt, readLocal: time.Now().Add(-3 * time.Second)}
	now := cached.databaseNow()
	if elapsed := now.Sub(readAt); elapsed < 3*time.Second || elapsed > time.Minute {
		t.Fatalf("databaseNow() = read time + %s, want about 3s", elapsed)
	}
	if got := (cachedInventory{readAt: readAt}).databaseNow(); !got.Equal(readAt) {
		t.Fatalf("databaseNow() without a local read time = %s, want the read time", got)
	}
}

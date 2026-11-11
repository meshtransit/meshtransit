package profile

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const displayTestID = "0123456789abcdef0123456789abcdef"

func TestDisplayStoreKeepsEachWritersFields(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "display")
	now := time.Date(2026, time.November, 11, 9, 0, 0, 0, time.UTC)
	store, err := OpenDisplayStore(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, found := store.Get(displayTestID); found {
		t.Fatal("a new store has a display")
	}
	if err := store.Update(displayTestID, func(display *Display) {
		display.CreatedByAddAccount, display.PreviousProfileID = true, "fedcba9876543210fedcba9876543210"
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(displayTestID, func(display *Display) {
		display.Network, display.Owner, display.Ownership = "Lab", "Alice", "member"
	}); err != nil {
		t.Fatal(err)
	}
	got, found := store.Get(displayTestID)
	if !found || !got.CreatedByAddAccount || got.PreviousProfileID == "" || got.Network != "Lab" ||
		got.Owner != "Alice" || got.Version != displayVersion || !got.UpdatedAt.Equal(now) {
		t.Fatalf("display = %+v, %t", got, found)
	}
	info, err := os.Stat(filepath.Join(dir, displayTestID+".json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("display file mode = %v, %v; want 0600", info, err)
	}
	if err := store.Remove(displayTestID); err != nil {
		t.Fatal(err)
	}
	if _, found := store.Get(displayTestID); found {
		t.Fatal("removed display still read")
	}
	if err := store.Remove(displayTestID); err != nil {
		t.Fatalf("removing twice: %v", err)
	}
}

// An unchanged display is not rewritten; a damaged one only loses names.
func TestDisplayStoreUnchangedAndDamaged(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "display")
	clock := time.Date(2026, time.November, 11, 9, 0, 0, 0, time.UTC)
	store, err := OpenDisplayStore(dir, func() time.Time { clock = clock.Add(time.Minute); return clock })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	set := func(display *Display) { display.Network = "Lab" }
	if err := store.Update(displayTestID, set); err != nil {
		t.Fatal(err)
	}
	first, _ := store.Get(displayTestID)
	if err := store.Update(displayTestID, set); err != nil {
		t.Fatal(err)
	}
	if second, _ := store.Get(displayTestID); !second.UpdatedAt.Equal(first.UpdatedAt) {
		t.Fatalf("an unchanged display was rewritten: %v then %v", first.UpdatedAt, second.UpdatedAt)
	}
	if err := os.WriteFile(filepath.Join(dir, displayTestID+".json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, found := store.Get(displayTestID); found {
		t.Fatal("a damaged display was read")
	}
	if err := store.Update(displayTestID, set); err != nil {
		t.Fatalf("a damaged display must be replaced: %v", err)
	}
	if got, found := store.Get(displayTestID); !found || got.Network != "Lab" {
		t.Fatalf("display = %+v, %t", got, found)
	}
	if err := store.Update("../escape", set); err == nil {
		t.Fatal("a non-profile ID was accepted")
	}
}

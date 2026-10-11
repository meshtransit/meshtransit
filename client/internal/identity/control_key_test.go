package identity

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestStoreStagesAndPromotesTheNextControlKey(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 11, 7, 8, 9, 0, time.UTC)
	dir := t.TempDir()
	store, err := openWith(dir, func() time.Time { return now }, testProtector(t, 0x19))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Create(t.Context(), testRecord(t, now)); err != nil {
		t.Fatal(err)
	}
	nextKey := []byte("control-public-next")
	nextFingerprint := "sha256:" + strings.Repeat("b", 64)

	staged, err := store.StageNextControlKey(t.Context(), testProfileID, nextKey, nextFingerprint)
	if err != nil {
		t.Fatalf("StageNextControlKey() error = %v", err)
	}
	if key, fingerprint := staged.NextControlKey(); string(key) != string(nextKey) || fingerprint != nextFingerprint {
		t.Fatalf("staged next key = %q %q", key, fingerprint)
	}
	if _, err := store.StageNextControlKey(t.Context(), testProfileID, []byte("control-public"),
		"sha256:"+strings.Repeat("a", 64)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("staging the current key as next: error = %v, want ErrInvalid", err)
	}

	// The staged key survives reopening the store.
	reopened, err := openWith(dir, func() time.Time { return now }, testProtector(t, 0x19))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	record, err := reopened.Get(t.Context(), testProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if key, _ := record.NextControlKey(); string(key) != string(nextKey) {
		t.Fatalf("reopened next key = %q", key)
	}

	if _, err := reopened.PromoteNextControlKey(t.Context(), testProfileID, []byte("other")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("promoting an unexpected key: error = %v, want ErrInvalid", err)
	}
	promoted, err := reopened.PromoteNextControlKey(t.Context(), testProfileID, nextKey)
	if err != nil {
		t.Fatalf("PromoteNextControlKey() error = %v", err)
	}
	material := promoted.Material()
	if string(material.ControlPublicKey) != string(nextKey) || promoted.ControlKeyFingerprint() != nextFingerprint {
		t.Fatalf("promoted control key = %q %q", material.ControlPublicKey, promoted.ControlKeyFingerprint())
	}
	if key, fingerprint := promoted.NextControlKey(); key != nil || fingerprint != "" {
		t.Fatalf("next key after promotion = %q %q", key, fingerprint)
	}

	cleared, err := reopened.StageNextControlKey(t.Context(), testProfileID, nil, "")
	if err != nil {
		t.Fatalf("clearing: error = %v", err)
	}
	if key, _ := cleared.NextControlKey(); key != nil {
		t.Fatalf("next key after clearing = %q", key)
	}
}

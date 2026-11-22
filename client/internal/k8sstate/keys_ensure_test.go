package k8sstate

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

func thirtyTwo(fill byte) func() ([]byte, error) {
	return func() ([]byte, error) { return bytes.Repeat([]byte{fill}, 32), nil }
}

func isThirtyTwo(value []byte) bool { return len(value) == 32 }

// A replica adds its own key once; later starts read it back.
func TestEnsureKeyAddsOnce(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	api.writeForeign("key-1", bytes.Repeat([]byte{1}, 32))
	cfg := api.config(t)
	value, added, err := EnsureKey(context.Background(), cfg, "key-0", thirtyTwo(7), isThirtyTwo)
	if err != nil || !added || !bytes.Equal(value, bytes.Repeat([]byte{7}, 32)) {
		t.Fatalf("EnsureKey() = %x, %t, %v", value, added, err)
	}
	if stored, ok := api.value("key-0"); !ok || !bytes.Equal(stored, value) {
		t.Fatalf("stored %x, %t", stored, ok)
	}
	if other, ok := api.value("key-1"); !ok || other[0] != 1 {
		t.Fatal("adding key-0 changed key-1")
	}
	again, added, err := EnsureKey(context.Background(), cfg, "key-0", thirtyTwo(9), isThirtyTwo)
	if err != nil || added || !bytes.Equal(again, value) {
		t.Fatalf("second EnsureKey() = %x, %t, %v", again, added, err)
	}
}

// Another writer adding the same key first wins; its value is kept.
func TestEnsureKeyKeepsAConcurrentWriter(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	cfg := api.config(t)
	racer := func() ([]byte, error) {
		api.writeForeign("key-0", bytes.Repeat([]byte{3}, 32))
		return bytes.Repeat([]byte{4}, 32), nil
	}
	value, added, err := EnsureKey(context.Background(), cfg, "key-0", racer, isThirtyTwo)
	if err != nil || added || value[0] != 3 {
		t.Fatalf("EnsureKey() = %x, %t, %v", value, added, err)
	}
	if _, conflicts := api.counts(); conflicts != 1 {
		t.Fatalf("%d conflicts", conflicts)
	}
}

func TestEnsureKeyRefuses(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	api.writeForeign("key-0", []byte("short"))
	cfg := api.config(t)
	if _, _, err := EnsureKey(context.Background(), cfg, "key-0", thirtyTwo(1), isThirtyTwo); !errors.Is(err,
		ErrKeyInvalid) {
		t.Fatalf("an unusable stored key: %v", err)
	}
	if stored, _ := api.value("key-0"); string(stored) != "short" {
		t.Fatal("an unusable stored key was replaced")
	}
	if _, _, err := EnsureKey(context.Background(), cfg, "key-1", func() ([]byte, error) {
		return []byte("bad"), nil
	}, isThirtyTwo); err == nil {
		t.Fatal("an unusable generated key was written")
	}
	api.queue(faultForbidden)
	if _, _, err := EnsureKey(context.Background(), cfg, "key-2", thirtyTwo(1), isThirtyTwo); err == nil {
		t.Fatal("a forbidden update reported success")
	}
	if _, ok := api.value("key-2"); ok {
		t.Fatal("a forbidden update wrote")
	}
	// A lost answer: the write landed; the next read finds it.
	api.queue(faultApplyThen500)
	value, _, err := EnsureKey(context.Background(), cfg, "key-3", thirtyTwo(5), isThirtyTwo)
	if err != nil || value[0] != 5 {
		t.Fatalf("after a lost answer: %x, %v", value, err)
	}
}

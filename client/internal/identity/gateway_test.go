package identity

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"
)

func gatewayStore(t *testing.T, now *time.Time) *Store {
	t.Helper()
	store, err := openWith(t.TempDir(), func() time.Time { return *now }, testProtector(t, 0x2a))
	if err != nil {
		t.Fatalf("openWith() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	record := testRecord(t, *now)
	record.isRegistered = true
	if err := store.Create(t.Context(), record); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	return store
}

// A gateway stages machine keys before it sends them, keeps them newest
// first, at most three, and promotes the one that proves: newer staged
// keys stay, older ones and the former key go.
func TestStore_GatewayMachineKeys(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 25, 9, 0, 0, 0, time.UTC)
	store := gatewayStore(t, &now)
	if _, err := store.StageMachineKeyRotation(t.Context(), testProfileID, []byte("m1"), now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("staging on an ordinary Device: %v", err)
	}
	if _, err := store.CompleteClusterJoin(t.Context(), testProfileID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an ordinary Device became a gateway: %v", err)
	}
	if _, err := store.SetRegistration(t.Context(), testProfileID, "", false); err != nil {
		t.Fatal(err)
	}
	marked, err := store.CompleteClusterJoin(t.Context(), testProfileID)
	if err != nil || !marked.IsGateway() || !marked.IsRegistered() {
		t.Fatalf("CompleteClusterJoin() = %v, %v", marked, err)
	}
	for _, staged := range []string{"m1", "m2", "m3"} {
		now = now.Add(time.Minute)
		record, err := store.StageMachineKeyRotation(t.Context(), testProfileID, []byte(staged), now)
		if err != nil || !record.LastKeyRotationAt().Equal(now) {
			t.Fatalf("StageMachineKeyRotation(%s) = %v, %v", staged, record.LastKeyRotationAt(), err)
		}
	}
	if _, err := store.StageMachineKeyRotation(t.Context(), testProfileID, []byte("m4"), now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a fourth staged key: %v", err)
	}
	reloaded, err := store.Get(t.Context(), testProfileID)
	if err != nil || !slices.Equal(texts(reloaded.PendingMachinePrivateKeys()), []string{"m3", "m2", "m1"}) {
		t.Fatalf("staged keys = %v, %v", texts(reloaded.PendingMachinePrivateKeys()), err)
	}
	if _, err := store.StageMachineKeyRotation(t.Context(), testProfileID, []byte("m2"), now); !errors.Is(err, ErrInvalid) {
		t.Fatalf("staging a key twice: %v", err)
	}
	promoted, err := store.PromoteMachineKey(t.Context(), testProfileID, []byte("m2"))
	if err != nil || string(promoted.Material().MachinePrivateKey) != "m2" ||
		!slices.Equal(texts(promoted.PendingMachinePrivateKeys()), []string{"m3"}) {
		t.Fatalf("PromoteMachineKey() = %s %v, %v", promoted.Material().MachinePrivateKey,
			texts(promoted.PendingMachinePrivateKeys()), err)
	}
	if _, err := store.PromoteMachineKey(t.Context(), testProfileID, []byte("m1")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("promoting a dropped key: %v", err)
	}
	abandoned, err := store.AbandonMachineKeyRotation(t.Context(), testProfileID, []byte("m3"))
	if err != nil || len(abandoned.PendingMachinePrivateKeys()) != 0 || string(abandoned.Material().MachinePrivateKey) != "m2" {
		t.Fatalf("AbandonMachineKeyRotation() = %v, %v", abandoned, err)
	}
	// New credentials end the gateway's state.
	replaced, err := store.ReplaceCredentials(t.Context(), testProfileID, []byte("fresh-machine"), []byte("fresh-node"))
	if err != nil || replaced.IsGateway() || len(replaced.PendingMachinePrivateKeys()) != 0 ||
		!replaced.LastKeyRotationAt().IsZero() {
		t.Fatalf("ReplaceCredentials() = %v, %v", replaced, err)
	}
}

// An ordinary Device's record is written exactly as before: no new field.
func TestRecord_OrdinaryFieldsUnchanged(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 25, 9, 0, 0, 0, time.UTC)
	record := testRecord(t, now)
	record.isRegistered = true
	encoded, err := json.Marshal(toPersisted(record))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(fields))
	for field := range fields {
		keys = append(keys, field)
	}
	slices.Sort(keys)
	want := []string{
		"control_key_fingerprint", "control_public_key", "created_at", "is_registered",
		"machine_private_key", "node_private_key", "profile_id", "updated_at", "version",
	}
	if !slices.Equal(keys, want) {
		t.Fatalf("ordinary record fields = %v, want %v", keys, want)
	}
}

func texts(values [][]byte) []string {
	out := make([]string, len(values))
	for index, value := range values {
		out[index] = string(value)
	}
	return out
}

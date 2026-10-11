package redis

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestClientParsesReplicaLoads(t *testing.T) {
	t.Parallel()

	var gotID string
	var gotSessions int
	var gotTTL time.Duration
	client := &Client{replicaLoad: func(_ context.Context, key, id string, sessions int, ttl time.Duration) ([]any, error) {
		if key != replicaLoadKey {
			t.Fatalf("key = %q", key)
		}
		gotID, gotSessions, gotTTL = id, sessions, ttl
		return []any{"a", "10", "b", "0"}, nil
	}}
	loads, err := client.PublishLoad(t.Context(), "a", 10, 30*time.Second)
	if err != nil || len(loads) != 2 || loads[0].Sessions != 10 || loads[1].ReplicaID != "b" {
		t.Fatalf("PublishLoad() = %+v, %v", loads, err)
	}
	if gotID != "a" || gotSessions != 10 || gotTTL != 30*time.Second {
		t.Fatalf("script args = %q %d %v", gotID, gotSessions, gotTTL)
	}
	if _, err := client.Loads(t.Context()); err != nil || gotID != "" {
		t.Fatalf("Loads() published %q, %v", gotID, err)
	}
	for name, raw := range map[string][]any{
		"odd":      {"a"},
		"negative": {"a", "-1"},
		"number":   {"a", "x"},
		"empty id": {"", "1"},
	} {
		client.replicaLoad = func(context.Context, string, string, int, time.Duration) ([]any, error) { return raw, nil }
		if _, err := client.Loads(t.Context()); !errors.Is(err, ErrReplicaLoad) {
			t.Errorf("%s: Loads() error = %v", name, err)
		}
	}
	if _, err := client.PublishLoad(t.Context(), "", 1, time.Minute); !errors.Is(err, ErrReplicaLoad) {
		t.Fatalf("PublishLoad(empty id) error = %v", err)
	}
}

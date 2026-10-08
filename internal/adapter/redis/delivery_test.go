package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/node"
)

func testDeliveryNode(t *testing.T) node.ID {
	t.Helper()
	id, err := node.ParseID("01890f00-0000-7000-8000-000000000301")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestClientRecordsAndTouchesDeliveryUnderOneKey(t *testing.T) {
	t.Parallel()
	nodeID := testDeliveryNode(t)
	delivered := time.Date(2026, time.October, 8, 12, 0, 0, 0, time.UTC)
	var gotKey string
	var gotArgs []int64
	var gotTTL time.Duration
	var touchKey string
	var touchArgs []int64
	client := &Client{
		recordDelivery: func(_ context.Context, key string, generation, networkRevision, policyRevision,
			deliveredAt int64, ttl time.Duration) (int64, error) {
			gotKey, gotTTL = key, ttl
			gotArgs = []int64{generation, networkRevision, policyRevision, deliveredAt}
			return 1, nil
		},
		touchDelivery: func(_ context.Context, key string, generation, seenAt int64, _ time.Duration) (int64, error) {
			touchKey, touchArgs = key, []int64{generation, seenAt}
			return 0, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	delivery := mapsession.Delivery{NodeID: nodeID, SessionGeneration: 4, NetworkRevision: 9, PolicyRevision: 3,
		DeliveredAt: delivered}
	if err := client.RecordDelivery(t.Context(), delivery); err != nil {
		t.Fatalf("RecordDelivery() error = %v", err)
	}
	wantKey := "meshtransit:v1:delivery:node:" + nodeID.String()
	if gotKey != wantKey || gotTTL != deliveryTTL ||
		len(gotArgs) != 4 || gotArgs[0] != 4 || gotArgs[1] != 9 || gotArgs[2] != 3 ||
		gotArgs[3] != delivered.UnixMilli() {
		t.Fatalf("record = %s %v %s", gotKey, gotArgs, gotTTL)
	}
	if err := client.TouchDelivery(t.Context(), nodeID, 4, delivered.Add(time.Minute)); err != nil {
		t.Fatalf("TouchDelivery() error = %v", err)
	}
	if touchKey != wantKey || touchArgs[0] != 4 || touchArgs[1] != delivered.Add(time.Minute).UnixMilli() {
		t.Fatalf("touch = %s %v", touchKey, touchArgs)
	}
}

func TestClientRejectsInvalidDeliveriesBeforeRedis(t *testing.T) {
	t.Parallel()
	called := false
	client := &Client{
		recordDelivery: func(context.Context, string, int64, int64, int64, int64, time.Duration) (int64, error) {
			called = true
			return 1, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	if err := client.RecordDelivery(t.Context(), mapsession.Delivery{}); !errors.Is(err, ErrInvalidOptions) || called {
		t.Fatalf("RecordDelivery(invalid) error = %v called = %t", err, called)
	}
}

func TestClientLoadsObservationsInOrder(t *testing.T) {
	t.Parallel()
	known, unknown := testDeliveryNode(t), testDeliveryNode(t)
	unknown[15] = 0x02
	var gotKeys []string
	client := &Client{
		loadDeliveries: func(_ context.Context, keys []string) ([]any, error) {
			gotKeys = keys
			return []any{
				"4", "9", "3", "1759924800000", "1759924860000", "1",
				"", "", "", "", "", "0",
			}, nil
		},
		metrics: newRedisMetrics(1, nil),
	}
	observations, err := client.LoadObservations(t.Context(), []node.ID{known, unknown})
	if err != nil {
		t.Fatalf("LoadObservations() error = %v", err)
	}
	if len(gotKeys) != 4 || gotKeys[0] != deliveryKeyForNode(known) || gotKeys[1] != presenceKeyForNode(known) {
		t.Fatalf("keys = %v", gotKeys)
	}
	first, second := observations[0], observations[1]
	if !first.Known || !first.Online || first.NetworkRevision != 9 || first.PolicyRevision != 3 ||
		first.SessionGeneration != 4 || first.SeenAt.Sub(first.DeliveredAt) != time.Minute {
		t.Fatalf("first = %+v", first)
	}
	if second.Known || second.Online {
		t.Fatalf("second = %+v", second)
	}
}

func TestClientRejectsCorruptObservations(t *testing.T) {
	t.Parallel()
	id := testDeliveryNode(t)
	for name, raw := range map[string][]any{
		"short":          {"4", "9"},
		"partial record": {"", "9", "", "", "", "0"},
		"bad number":     {"x", "9", "3", "1", "1", "0"},
		"bad presence":   {"", "", "", "", "", "2"},
		"seen before":    {"4", "9", "3", "1759924860000", "1759924800000", "0"},
		"non string":     {int64(4), "9", "3", "1", "1", "0"},
	} {
		client := &Client{
			loadDeliveries: func(context.Context, []string) ([]any, error) { return raw, nil },
			metrics:        newRedisMetrics(1, nil),
		}
		if _, err := client.LoadObservations(t.Context(), []node.ID{id}); !errors.Is(err, ErrLoadDeliveries) {
			t.Errorf("%s: error = %v, want ErrLoadDeliveries", name, err)
		}
	}
}

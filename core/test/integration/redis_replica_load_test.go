//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/control/rebalance"
)

// assertRedisReplicaLoads checks the control load registry script: loads
// expire by Redis time, withdrawal is immediate. Other processes of the
// suite may publish too, so only this test's replicas are compared.
func assertRedisReplicaLoads(ctx context.Context, t *testing.T, client *redisadapter.Client) {
	t.Helper()
	const short, long, gone = "integration-short", "integration-long", "integration-gone"
	ours := func(loads []rebalance.ReplicaLoad) map[string]int {
		found := map[string]int{}
		for _, load := range loads {
			if load.ReplicaID == short || load.ReplicaID == long || load.ReplicaID == gone {
				found[load.ReplicaID] = load.Sessions
			}
		}
		return found
	}
	if _, err := client.PublishLoad(ctx, short, 10, time.Second); err != nil {
		t.Fatalf("PublishLoad(short) error = %v", err)
	}
	if _, err := client.PublishLoad(ctx, gone, 3, 10*time.Second); err != nil {
		t.Fatalf("PublishLoad(gone) error = %v", err)
	}
	loads, err := client.PublishLoad(ctx, long, 5, 10*time.Second)
	if err != nil {
		t.Fatalf("PublishLoad(long) error = %v", err)
	}
	if got := ours(loads); len(got) != 3 || got[short] != 10 || got[long] != 5 || got[gone] != 3 {
		t.Fatalf("published loads = %v", got)
	}
	if err := client.WithdrawLoad(ctx, gone); err != nil {
		t.Fatalf("WithdrawLoad() error = %v", err)
	}
	time.Sleep(1200 * time.Millisecond)
	loads, err = client.Loads(ctx)
	if err != nil {
		t.Fatalf("Loads() error = %v", err)
	}
	if got := ours(loads); len(got) != 1 || got[long] != 5 {
		t.Fatalf("loads after expiry and withdrawal = %v, want only %s", got, long)
	}
	if err := client.WithdrawLoad(ctx, long); err != nil {
		t.Fatalf("WithdrawLoad(long) error = %v", err)
	}
}

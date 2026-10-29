//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	redisadapter "meshtransit.net/core/internal/adapter/redis"
	"meshtransit.net/core/internal/domain/kubeaudit"
)

// assertRedisKubernetesOperationLimits: one script takes n operations from
// a Workspace's and a gateway's buckets, or from neither (K1b0 §6).
func assertRedisKubernetesOperationLimits(ctx context.Context, t *testing.T, client *redisadapter.Client) {
	t.Helper()
	limits := kubeaudit.Limits{Gateway: kubeaudit.Rate{PerSecond: 1, Burst: 10},
		Workspace: kubeaudit.Rate{PerSecond: 1, Burst: 15}, Replica: kubeaudit.DefaultLimits.Replica}
	workspace := mustPublicID(t).String()
	take := func(gateway string, n int) (time.Duration, bool) {
		t.Helper()
		wait, taken, err := client.TakeKubernetesOperations(ctx, workspace, gateway, n, limits)
		if err != nil {
			t.Fatalf("TakeKubernetesOperations() error = %v", err)
		}
		return wait, taken
	}
	if _, taken := take("g1", 10); !taken {
		t.Fatal("a gateway's burst was refused")
	}
	if wait, taken := take("g1", 1); taken || wait < 500*time.Millisecond {
		t.Fatalf("over the gateway's burst: %v, %v", wait, taken)
	}
	// g2's bucket holds 10, the Workspace's 5: refused, and nothing taken.
	if _, taken := take("g2", 6); taken {
		t.Fatal("over the Workspace's bucket was taken")
	}
	if _, taken := take("g2", 5); !taken {
		t.Fatal("the Workspace's last tokens were refused")
	}
	if _, _, err := client.TakeKubernetesOperations(ctx, "", "g", 1, limits); err == nil {
		t.Fatal("a take without a Workspace was sent")
	}
}

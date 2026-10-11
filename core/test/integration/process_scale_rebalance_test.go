//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/adapter/mtcp/mtcptest"
)

// measureScaleRebalance starts a second control process, points every
// client's next dial at it (a load balancer placing reconnecting nodes
// elsewhere) and waits until the first process holds no more than its fair
// share plus the rebalancing tolerance, and the registry counts every
// session on two replicas.
func measureScaleRebalance(ctx context.Context, t *testing.T, binary string, first readyControlProcess,
	clients []*mtcptest.Client, collector *scaleCollector, sessions int) string {
	t.Helper()
	secondHealth, secondControl := reserveLoopbackAddress(t), reserveLoopbackAddress(t)
	// Stopped by the test's cleanup, after the collector closed its streams.
	startScaleControlOnly(t, binary, secondHealth, secondControl, sessions)
	for _, client := range clients {
		client.SetControlAddress(secondControl)
	}
	reconnectsBefore := collector.reconnectCount()
	fair := int(math.Ceil(float64(sessions) / 2))
	allowed := fair + max(32, int(math.Ceil(float64(fair)*0.10)))
	started := time.Now()
	deadline := started.Add(scalePhaseTimeout)
	var firstSessions, secondSessions int
	var settledAt time.Duration
	for time.Now().Before(deadline) && ctx.Err() == nil {
		firstSessions = scaleSessionsActive(ctx, t, first.healthAddress)
		secondSessions = scaleSessionsActive(ctx, t, secondHealth)
		if firstSessions <= allowed && firstSessions+secondSessions == sessions {
			settledAt = time.Since(started)
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if settledAt == 0 {
		t.Fatalf("rebalance did not settle in %v: first %d (allowed %d), second %d of %d sessions; stderr: %s",
			scalePhaseTimeout, firstSessions, allowed, secondSessions, sessions, scaleTail(first.process.stderr.String()))
	}
	// The registry catches up within one publication interval.
	var total scaleTotal
	for wait := time.Now().Add(10 * time.Second); time.Now().Before(wait); time.Sleep(250 * time.Millisecond) {
		if total = scaleSessionTotal(ctx, t, secondHealth); total.Sessions == sessions && total.Replicas == 2 {
			break
		}
	}
	if total.Sessions != sessions || total.Replicas != 2 {
		t.Fatalf("scale endpoint = %+v, want %d sessions on 2 replicas", total, sessions)
	}
	collector.failOnUnexpected(t, first)
	return fmt.Sprintf("first %d -> %d sessions (allowed %d), second %d, settled in %v with %d reconnects; "+
		"scale endpoint %d sessions on %d replicas", sessions, firstSessions, allowed, secondSessions,
		settledAt.Round(100*time.Millisecond), collector.reconnectCount()-reconnectsBefore, total.Sessions, total.Replicas)
}

type scaleTotal struct {
	Sessions int `json:"sessions"`
	Replicas int `json:"replicas"`
}

func scaleSessionTotal(ctx context.Context, t *testing.T, healthAddress string) scaleTotal {
	t.Helper()
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client := integrationHTTPClient()
	defer client.CloseIdleConnections()
	status, body, err := integrationGET(readCtx, client, healthAddress, "/scale/v1/sessions")
	var total scaleTotal
	if err != nil || status != http.StatusOK || json.Unmarshal([]byte(body), &total) != nil {
		t.Fatalf("read scale endpoint = (%d, %q, %v)", status, body, err)
	}
	return total
}

func scaleSessionsActive(ctx context.Context, t *testing.T, healthAddress string) int {
	t.Helper()
	readCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client := integrationHTTPClient()
	defer client.CloseIdleConnections()
	status, body, err := integrationGET(readCtx, client, healthAddress, "/metrics")
	if err != nil || status != http.StatusOK {
		t.Fatalf("read metrics = (%d, %v)", status, err)
	}
	for line := range strings.SplitSeq(body, "\n") {
		if value, found := strings.CutPrefix(line, "meshtransit_mtcp_sessions_active "); found {
			sessions, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
			if err != nil {
				t.Fatalf("parse sessions %q: %v", value, err)
			}
			return int(sessions)
		}
	}
	t.Fatal("meshtransit_mtcp_sessions_active missing")
	return 0
}

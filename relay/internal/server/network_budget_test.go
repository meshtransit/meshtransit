package server

import (
	"testing"
	"time"

	"meshtransit.net/shared/mtrp"
)

// TestRelayBoundsANetworksBandwidth sends from two sessions of one Network:
// together they get the Network's budget, while another Network keeps its
// own.
func TestRelayBoundsANetworksBandwidth(t *testing.T) {
	t.Parallel()
	h := newRelay(t, func(c *Config) { c.NetworkBytesPerSecond = 10 })
	a, c, b := h.newClient(zoneA), h.newClient(zoneA), h.newClient(zoneA, zoneB)
	other, peer := h.newClient(zoneB), h.newClient(zoneB)
	routeA, _ := openRoute(t, a, b)
	routeC, _ := openRoute(t, c, b)
	routeOther, _ := openRoute(t, other, peer)

	a.sendData(a.addr, routeA, []byte("123456"))
	c.sendData(c.addr, routeC, []byte("123456")) // 12 bytes of zone A in one second
	if got := h.metrics.get("data:network_rate_limited"); got != 1 {
		t.Fatalf("network-limited frames = %d, want the second sender's", got)
	}
	other.sendData(other.addr, routeOther, []byte("123456"))
	if got := h.metrics.get("data:network_rate_limited"); got != 1 {
		t.Fatalf("another Network was limited too: %d", got)
	}
}

func TestNetworkBudgetsForgetIdleNetworks(t *testing.T) {
	t.Parallel()
	budgets := newNetworkBudgets(100)
	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	if !budgets.allow(zoneA.ID, 100, now) || budgets.allow(zoneA.ID, 1, now) {
		t.Fatal("the bucket does not hold one second of the rate")
	}
	held := func() int {
		count := 0
		for index := range budgets.shards {
			count += len(budgets.shards[index].buckets)
		}
		return count
	}
	budgets.prune(now.Add(idleNetworkBudget - time.Second))
	if held() != 1 {
		t.Fatal("a Network forwarding lately was forgotten")
	}
	// Pruning runs at most every pruneNetworkBudgets.
	budgets.prune(now.Add(idleNetworkBudget))
	if held() != 1 {
		t.Fatal("pruned twice within the prune interval")
	}
	budgets.prune(now.Add(idleNetworkBudget + pruneNetworkBudgets))
	if held() != 0 {
		t.Fatal("an idle Network was kept")
	}
}

func TestNetworkZoneIsTheTicketsFirstNetworkZone(t *testing.T) {
	t.Parallel()
	contract := mtrp.Zone{Kind: mtrp.ZoneTrustContract, ID: [16]byte{0xc}}
	if id := networkZone(mtrp.Ticket{Zones: []mtrp.Zone{zoneA, contract}}); id != zoneA.ID {
		t.Fatalf("networkZone = %x", id)
	}
	// A ticket without a Network zone shares the all-zero budget.
	if id := networkZone(mtrp.Ticket{Zones: []mtrp.Zone{contract}}); id != ([16]byte{}) {
		t.Fatalf("networkZone of a contract-only ticket = %x", id)
	}
}

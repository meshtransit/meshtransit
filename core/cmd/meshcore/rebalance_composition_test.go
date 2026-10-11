package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"meshtransit.net/core/internal/control/rebalance"
	"meshtransit.net/core/internal/platform/config"
)

type rebalanceRegistryFixture struct{}

func (rebalanceRegistryFixture) PublishLoad(context.Context, string, int, time.Duration) ([]rebalance.ReplicaLoad, error) {
	return nil, nil
}

func (rebalanceRegistryFixture) WithdrawLoad(context.Context, string) error { return nil }

type rebalancePoolFixture struct{}

func (rebalancePoolFixture) Sessions() int                                { return 0 }
func (rebalancePoolFixture) Shed(context.Context, int, time.Duration) int { return 0 }

func TestComposeRebalanceValidatesTheInterval(t *testing.T) {
	t.Parallel()
	logger := slog.New(slog.DiscardHandler)
	valid := config.ControlConfig{Rebalance: true, RebalanceInterval: 15 * time.Second}
	if balancer, err := composeRebalance(valid, rebalanceRegistryFixture{}, rebalancePoolFixture{}, logger); err != nil ||
		balancer == nil {
		t.Fatalf("composeRebalance() = %v, %v", balancer, err)
	}
	if _, err := composeRebalance(config.ControlConfig{}, rebalanceRegistryFixture{}, rebalancePoolFixture{},
		logger); err == nil {
		t.Fatal("composeRebalance() accepted a zero interval")
	}
}

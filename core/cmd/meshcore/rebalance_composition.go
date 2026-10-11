package main

import (
	"errors"
	"log/slog"

	"meshtransit.net/core/internal/control/rebalance"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidRebalanceComposition = errors.New("invalid rebalance composition")

// Rebalancing bounds: a replica keeps up to 10% (at least 32 sessions)
// above its fair share and sheds at most 5% of its sessions per step, each
// shed node returning within one interval.
const (
	rebalanceTolerance       = 0.10
	rebalanceMinExcess       = 32
	rebalanceMaxShedFraction = 0.05
)

// composeRebalance builds the replica's load publisher and balancer. It
// always publishes (the autoscaler reads the total); it sheds only when
// rebalancing is on, and never as the only replica.
func composeRebalance(controlConfig config.ControlConfig, registry rebalance.Registry, pool rebalance.SessionPool,
	logger *slog.Logger) (*rebalance.Balancer, error) {
	replicaID, err := publicid.New()
	if err != nil {
		return nil, errors.Join(errInvalidRebalanceComposition, err)
	}
	balancer, err := rebalance.New(registry, pool, rebalance.Options{
		ReplicaID:       replicaID.String(),
		Interval:        controlConfig.RebalanceInterval,
		Shed:            controlConfig.Rebalance,
		Tolerance:       rebalanceTolerance,
		MinExcess:       rebalanceMinExcess,
		MaxShedFraction: rebalanceMaxShedFraction,
		ReconnectWindow: controlConfig.RebalanceInterval,
		Logger:          logger,
	})
	if err != nil {
		return nil, errors.Join(errInvalidRebalanceComposition, err)
	}
	return balancer, nil
}

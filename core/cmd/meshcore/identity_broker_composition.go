package main

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/platform/app"
)

var (
	errInvalidIdentityBrokerComposition = errors.New("invalid identity broker composition")
)

type identityBrokerComposition struct {
	checkers []app.DependencyChecker
	services []app.OwnedService
	metrics  []prometheus.Collector
}

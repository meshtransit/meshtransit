package main

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/app"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	errInvalidIdentityBrokerComposition = errors.New("invalid identity broker composition")
)

type identityBrokerComposition struct {
	checkers []app.DependencyChecker
	services []app.OwnedService
	metrics  []prometheus.Collector
}

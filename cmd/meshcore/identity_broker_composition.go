package main

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/app"
)

var (
	errInvalidIdentityBrokerComposition = errors.New("invalid identity broker composition")
)

type identityBrokerComposition struct {
	checkers []app.DependencyChecker
	services []app.OwnedService
}

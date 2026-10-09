//go:build !dexbroker

package main

import (
	"context"
	"errors"
	"log/slog"

	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

var errIdentityBrokerUnavailable = errors.New("identity broker support is unavailable in this binary")

func composeIdentityBroker(
	context.Context,
	config.IdentityConfig,
	*resourceOwner,
	*slog.Logger,
) (identityBrokerComposition, error) {
	return identityBrokerComposition{}, errIdentityBrokerUnavailable
}

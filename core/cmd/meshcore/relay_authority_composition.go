package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"meshtransit.net/core/internal/adapter/relayauthority"
	"meshtransit.net/core/internal/platform/clientip"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/shared/mtrp"
)

var errInvalidRelayAuthorityComposition = errors.New("invalid relay authority composition")

// composeRelayAuthority builds the publisher that signs relay state and the
// relay map, and the handler that serves them on the control listener.
func composeRelayAuthority(
	ctx context.Context,
	cfg config.RelayAuthorityConfig,
	logger *slog.Logger,
) (*relayauthority.Publisher, *relayauthority.Handler, error) {
	signer, next, err := cfg.SigningKeys(ctx)
	if err != nil {
		return nil, nil, errors.Join(errInvalidRelayAuthorityComposition, err)
	}
	var relayMap *mtrp.RelayMap
	if cfg.MapFile != "" {
		loaded, err := relayauthority.LoadMap(ctx, cfg.MapFile, cfg.MapDigest, time.Now())
		if err != nil {
			return nil, nil, errors.Join(errInvalidRelayAuthorityComposition, err)
		}
		relayMap = &loaded
	}
	publisher, err := relayauthority.NewPublisher(relayauthority.Options{
		Signer: signer,
		Next:   next,
		Map:    relayMap,
		Drain:  cfg.Drain,
		Logger: logger,
	})
	if err != nil {
		return nil, nil, errors.Join(errInvalidRelayAuthorityComposition, err)
	}
	clients, err := clientip.NewResolver(cfg.TrustedProxyPrefixes)
	if err != nil {
		return nil, nil, errors.Join(errInvalidRelayAuthorityComposition, err)
	}
	return publisher, relayauthority.NewHandler(publisher, clients), nil
}

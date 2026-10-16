package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/adapter/relayauthority"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/relay"
	"meshtransit.net/core/internal/platform/clientip"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/shared/mtrp"
)

var errInvalidRelayAuthorityComposition = errors.New("invalid relay authority composition")

// relayAuthority is the composed Interchange authority of a control process.
type relayAuthority struct {
	publisher *relayauthority.Publisher
	handler   *relayauthority.Handler
	access    mapsession.RelayAccess // nil unless tickets are enabled
	directory relay.Directory        // derived from the relay map, when there is one
	// directories returns a Network's directory with its Private
	// Interchange regions; nil without a relay map.
	directories func(network.ID) (relay.Directory, error)
}

// composeRelayAuthority builds the publisher that signs relay state and the
// relay map, the handler that serves them on the control listener, and,
// when a ticket deployment is configured, the issuer of node relay grants.
// Revocations come from PostgreSQL when a runtime pool is available.
func composeRelayAuthority(
	ctx context.Context,
	cfg config.RelayAuthorityConfig,
	runtime *postgres.Pool,
	logger *slog.Logger,
) (relayAuthority, error) {
	signer, next, err := cfg.SigningKeys(ctx)
	if err != nil {
		return relayAuthority{}, errors.Join(errInvalidRelayAuthorityComposition, err)
	}
	var relayMap *mtrp.RelayMap
	if cfg.MapFile != "" {
		loaded, err := relayauthority.LoadMap(ctx, cfg.MapFile, cfg.MapDigest, time.Now())
		if err != nil {
			return relayAuthority{}, errors.Join(errInvalidRelayAuthorityComposition, err)
		}
		relayMap = &loaded
	}
	options := relayauthority.Options{
		Signer: signer,
		Next:   next,
		Map:    relayMap,
		Drain:  cfg.Drain,
		Logger: logger,
	}
	if runtime != nil {
		store, err := postgres.NewRelayRevocationStore(runtime)
		if err != nil {
			return relayAuthority{}, errors.Join(errInvalidRelayAuthorityComposition, err)
		}
		options.Revocations = relayRevocationSource{store: store}
		private, err := postgres.NewPrivateInterchangeDirectoryStore(runtime)
		if err != nil {
			return relayAuthority{}, errors.Join(errInvalidRelayAuthorityComposition, err)
		}
		options.Private = private
	}
	publisher, err := relayauthority.NewPublisher(options)
	if err != nil {
		return relayAuthority{}, errors.Join(errInvalidRelayAuthorityComposition, err)
	}
	clients, err := clientip.NewResolver(cfg.TrustedProxyPrefixes)
	if err != nil {
		return relayAuthority{}, errors.Join(errInvalidRelayAuthorityComposition, err)
	}
	composed := relayAuthority{publisher: publisher, handler: relayauthority.NewHandler(publisher, clients)}
	if relayMap != nil {
		// The shared directory carries the combined version, like every map.
		directory, err := relayauthority.Directory(relayauthority.NetworkMap(*relayMap, nil, 0))
		if err != nil {
			return relayAuthority{}, errors.Join(errInvalidRelayAuthorityComposition, err)
		}
		composed.directory = directory
		composed.directories = publisher.DirectoryFor
	}
	if cfg.TicketDeployment != nil {
		issuer, err := relayauthority.NewIssuer(publisher, *cfg.TicketDeployment)
		if err != nil {
			return relayAuthority{}, errors.Join(errInvalidRelayAuthorityComposition, err)
		}
		composed.access = issuer
	}
	return composed, nil
}

// relayRevocationSource adapts the PostgreSQL read to the publisher.
type relayRevocationSource struct {
	store *postgres.RelayRevocationStore
}

func (source relayRevocationSource) RelayRevocations(ctx context.Context, lookback time.Duration) (relayauthority.Revoked, error) {
	revoked, err := source.store.ReadRelayRevocations(ctx, lookback)
	if err != nil {
		return relayauthority.Revoked{}, err
	}
	return relayauthority.Revoked{NodeKeys: revoked.NodeKeys, TrustContracts: revoked.TrustContracts}, nil
}

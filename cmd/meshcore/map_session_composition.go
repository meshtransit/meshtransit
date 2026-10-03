package main

import (
	"context"
	"errors"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/adapter/relayfile"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/relay"
)

var errInvalidMapSessionComposition = errors.New("invalid map session composition")

func composeMapSession(
	mapConfig config.ControlMapConfig,
	runtimePool *postgresadapter.Pool,
	endpoints mapsession.EndpointObserver,
	connectivity mapsession.ConnectivityStore,
	relayDirectory relay.Directory,
) (*mapsession.Service, error) {
	if runtimePool == nil || endpoints == nil || connectivity == nil || !relayDirectory.IsValid() {
		return nil, errInvalidMapSessionComposition
	}
	store, err := postgresadapter.NewMapSessionStore(
		runtimePool,
		postgresadapter.MapSessionOptions{
			EnableDeviceAliases: mapConfig.EnableDeviceAliases,
			StatementTimeout:    mapConfig.StatementTimeout,
			IdleTimeout:         mapConfig.TransactionIdleLimit,
			PeerCandidateLimit:  mapsession.MaximumPeerCandidates,
			PolicyRuleLimit:     mapsession.MaximumPacketPolicyRules,
			RelayDirectory:      relayDirectory,
		},
	)
	if err != nil {
		return nil, errors.Join(errInvalidMapSessionComposition, err)
	}
	return newMapSessionService(mapConfig, store, endpoints, connectivity)
}

func loadRelayDirectory(
	ctx context.Context,
	directoryConfig config.RelayDirectoryConfig,
) (relay.Directory, error) {
	if ctx == nil {
		return relay.Directory{}, errInvalidMapSessionComposition
	}
	path, digest, err := directoryConfig.Values()
	if err != nil {
		return relay.Directory{}, errors.Join(errInvalidMapSessionComposition, err)
	}
	directory, err := relayfile.Load(ctx, path, digest)
	if err != nil {
		return relay.Directory{}, errors.Join(errInvalidMapSessionComposition, err)
	}
	return directory, nil
}

func composeMapStream(
	mapConfig config.ControlMapConfig,
	snapshots mapsession.SnapshotOpener,
	presence mapsession.PresenceStore,
	revisions mapsession.RevisionWatcher,
	connectivity mapsession.ConnectivityWatcher,
) (*mapsession.StreamService, error) {
	replicaID, err := publicid.New()
	if err != nil {
		return nil, errors.Join(errInvalidMapSessionComposition, err)
	}
	return newMapStreamService(
		mapConfig,
		snapshots,
		presence,
		revisions,
		connectivity,
		replicaID,
	)
}

func newMapStreamService(
	mapConfig config.ControlMapConfig,
	snapshots mapsession.SnapshotOpener,
	presence mapsession.PresenceStore,
	revisions mapsession.RevisionWatcher,
	connectivity mapsession.ConnectivityWatcher,
	replicaID publicid.ID,
) (*mapsession.StreamService, error) {
	service, err := mapsession.NewStreamService(
		snapshots,
		presence,
		revisions,
		connectivity,
		mapsession.StreamOptions{
			ReplicaID:           replicaID,
			SnapshotTimeout:     mapConfig.RequestTimeout,
			PresenceTTL:         mapConfig.PresenceTTL,
			CoordinationTimeout: mapConfig.CoordinationTimeout,
			KeepAliveInterval:   mapConfig.KeepAliveInterval,
			ReconcileInterval:   mapConfig.ReconcileInterval,
		},
	)
	if err != nil {
		return nil, errors.Join(errInvalidMapSessionComposition, err)
	}
	return service, nil
}

func newMapSessionService(
	mapConfig config.ControlMapConfig,
	store mapsession.SnapshotStore,
	endpoints mapsession.EndpointObserver,
	connectivity mapsession.ConnectivityStore,
) (*mapsession.Service, error) {
	if store == nil || endpoints == nil || connectivity == nil {
		return nil, errInvalidMapSessionComposition
	}
	service, err := mapsession.NewService(store, endpoints, connectivity, mapsession.ServiceOptions{
		EndpointTTL:     mapConfig.PresenceTTL,
		EndpointTimeout: mapConfig.CoordinationTimeout,
	})
	if err != nil {
		return nil, errors.Join(errInvalidMapSessionComposition, err)
	}
	return service, nil
}

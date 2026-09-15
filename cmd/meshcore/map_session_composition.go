package main

import (
	"errors"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

var errInvalidMapSessionComposition = errors.New("invalid map session composition")

func composeMapSession(
	mapConfig config.ControlMapConfig,
	runtimePool *postgresadapter.Pool,
	endpoints mapsession.EndpointObserver,
	connectivity mapsession.ConnectivityStore,
) (*mapsession.Service, error) {
	if runtimePool == nil || endpoints == nil || connectivity == nil {
		return nil, errInvalidMapSessionComposition
	}
	store, err := postgresadapter.NewMapSessionStore(
		runtimePool,
		postgresadapter.MapSessionOptions{
			StatementTimeout:   mapConfig.StatementTimeout,
			IdleTimeout:        mapConfig.TransactionIdleLimit,
			PeerCandidateLimit: mapsession.MaximumPeerCandidates,
			PolicyRuleLimit:    mapsession.MaximumPacketPolicyRules,
		},
	)
	if err != nil {
		return nil, errors.Join(errInvalidMapSessionComposition, err)
	}
	return newMapSessionService(mapConfig, store, endpoints, connectivity)
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

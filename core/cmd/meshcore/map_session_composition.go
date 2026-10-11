package main

import (
	"context"
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	postgresmapsession "meshtransit.net/core/internal/adapter/postgres/mapsession"
	"meshtransit.net/core/internal/adapter/relayfile"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/relay"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidMapSessionComposition = errors.New("invalid map session composition")

func composeMapSession(
	mapConfig config.ControlMapConfig,
	runtimePool *postgresadapter.Pool,
	endpoints mapsession.EndpointObserver,
	connectivity mapsession.ConnectivityStore,
	relayDirectory relay.Directory,
	relayDirectories func(network.ID) (relay.Directory, error),
) (*mapsession.Service, prometheus.Collector, error) {
	if runtimePool == nil || endpoints == nil || connectivity == nil || !relayDirectory.IsValid() {
		return nil, nil, errInvalidMapSessionComposition
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
			RelayDirectories:    relayDirectories,
			// One inventory read answers for a revision for at most one
			// reconcile interval, as a direct read would be repeated.
			SharedInventory:           mapConfig.SharedInventory,
			InventoryStatementTimeout: mapConfig.InventoryStatementTimeout,
			InventoryMaxAge:           mapConfig.ReconcileInterval,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidMapSessionComposition, err)
	}
	service, err := newMapSessionService(mapConfig, store, endpoints, connectivity)
	if err != nil {
		return nil, nil, err
	}
	return service, newMapInventoryCollector(store.InventoryStats), nil
}

// mapInventoryCollector exports how map snapshots got their candidates and
// the shadow check of the Network policy expansion (scale-out S1/S2).
type mapInventoryCollector struct {
	stats      func() postgresmapsession.InventoryStats
	snapshots  *prometheus.Desc
	reads      *prometheus.Desc
	mismatches *prometheus.Desc
}

func newMapInventoryCollector(stats func() postgresmapsession.InventoryStats) *mapInventoryCollector {
	return &mapInventoryCollector{
		stats: stats,
		snapshots: prometheus.NewDesc("meshtransit_map_snapshots_total",
			"Map snapshots by candidate source: shared Network inventory or direct read.", []string{"source"}, nil),
		reads: prometheus.NewDesc("meshtransit_map_inventory_reads_total",
			"Network inventory reads (one per Network revision per replica when shared).", nil, nil),
		// Alert on: increase(meshtransit_map_inventory_policy_mismatches_total[15m]) > 0
		mismatches: prometheus.NewDesc("meshtransit_map_inventory_policy_mismatches_total",
			"Devices whose policy expanded from the Network policy differed from their own read.", nil, nil),
	}
}

func (collector *mapInventoryCollector) Describe(descriptions chan<- *prometheus.Desc) {
	descriptions <- collector.snapshots
	descriptions <- collector.reads
	descriptions <- collector.mismatches
}

func (collector *mapInventoryCollector) Collect(metrics chan<- prometheus.Metric) {
	stats := collector.stats()
	metrics <- prometheus.MustNewConstMetric(collector.snapshots, prometheus.CounterValue, float64(stats.Shared), "shared")
	metrics <- prometheus.MustNewConstMetric(collector.snapshots, prometheus.CounterValue, float64(stats.Direct), "direct")
	metrics <- prometheus.MustNewConstMetric(collector.reads, prometheus.CounterValue, float64(stats.Reads))
	metrics <- prometheus.MustNewConstMetric(collector.mismatches, prometheus.CounterValue, float64(stats.PolicyMismatches))
}

func loadRelayDirectory(
	ctx context.Context,
	directoryConfig *config.RelayDirectoryConfig,
) (relay.Directory, error) {
	if ctx == nil || directoryConfig == nil {
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
	delivery interface {
		mapsession.DeliveryRecorder
		mapsession.EnforcementRecorder
	},
	relayAccess mapsession.RelayAccess,
) (*mapsession.StreamService, error) {
	replicaID, err := publicid.New()
	if err != nil {
		return nil, errors.Join(errInvalidMapSessionComposition, err)
	}
	service, err := newMapStreamService(
		mapConfig,
		snapshots,
		presence,
		revisions,
		connectivity,
		replicaID,
	)
	if err != nil {
		return nil, err
	}
	// Policy distribution status (R1-65): record what each Device last
	// received, and (R1-69) what it reports it enforces.
	recorded, err := service.WithDeliveryRecorder(delivery)
	if err != nil {
		return nil, errors.Join(errInvalidMapSessionComposition, err)
	}
	recorded, err = recorded.WithEnforcementRecorder(delivery)
	if err != nil {
		return nil, errors.Join(errInvalidMapSessionComposition, err)
	}
	if relayAccess == nil {
		return recorded, nil
	}
	granted, err := recorded.WithRelayAccess(relayAccess)
	if err != nil {
		return nil, errors.Join(errInvalidMapSessionComposition, err)
	}
	return granted, nil
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
			FilterDigest:        mtcpadapter.PacketFilterDigest,
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

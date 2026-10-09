package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/platform/config"
)

func TestLoadRelayDirectoryUsesValidatedDigestPinnedFile(t *testing.T) {
	t.Parallel()

	document := []byte(`{"schema_version":1,"revision":7,"regions":[{"id":1,"code":"sin","name":"Singapore","nodes":[{"name":"1a","host_name":"relay.example.com","cert_name":"","ipv4":"192.0.2.10","ipv6":"2001:db8::10","stun_port":3478,"relay_port":443,"stun_only":false}]}]}`)
	digest := sha256.Sum256(document)
	path := filepath.Join(t.TempDir(), "relay-directory.json")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	directoryConfig, err := config.NewRelayDirectoryConfig(
		path,
		"sha256:"+hex.EncodeToString(digest[:]),
	)
	if err != nil {
		t.Fatalf("config.NewRelayDirectoryConfig() error = %v", err)
	}
	directory, err := loadRelayDirectory(t.Context(), directoryConfig)
	if err != nil || !directory.IsValid() || directory.Revision() != 7 {
		t.Fatalf("loadRelayDirectory() = (%v, %v)", directory, err)
	}
}

func TestNewMapSessionServiceValidatesComposition(t *testing.T) {
	t.Parallel()

	mapConfig := config.ControlMapConfig{
		PresenceTTL:         30 * time.Second,
		CoordinationTimeout: time.Second,
	}
	if _, err := newMapSessionService(
		mapConfig,
		nil,
		mapEndpointObserverFixture{},
		mapConnectivityStoreFixture{},
	); !errors.Is(
		err,
		errInvalidMapSessionComposition,
	) {
		t.Fatalf("newMapSessionService(nil store) error = %v, want composition error", err)
	}
	if _, err := newMapSessionService(
		mapConfig,
		mapSnapshotStoreFixture{},
		nil,
		mapConnectivityStoreFixture{},
	); !errors.Is(
		err,
		errInvalidMapSessionComposition,
	) {
		t.Fatalf("newMapSessionService(nil observer) error = %v, want composition error", err)
	}
	service, err := newMapSessionService(
		mapConfig,
		mapSnapshotStoreFixture{},
		mapEndpointObserverFixture{},
		mapConnectivityStoreFixture{},
	)
	if err != nil {
		t.Fatalf("newMapSessionService() error = %v", err)
	}
	if service == nil {
		t.Fatal("newMapSessionService() returned nil service")
	}
}

func TestNewMapStreamServiceValidatesComposition(t *testing.T) {
	t.Parallel()

	replicaID, err := publicid.Parse("01890f00-0000-7000-8000-000000000901")
	if err != nil {
		t.Fatalf("publicid.Parse() error = %v", err)
	}
	mapConfig := config.ControlMapConfig{
		RequestTimeout:       time.Second,
		StatementTimeout:     time.Second,
		TransactionIdleLimit: time.Second,
		PresenceTTL:          9 * time.Second,
		CoordinationTimeout:  time.Second,
		KeepAliveInterval:    4 * time.Second,
		ReconcileInterval:    5 * time.Second,
	}
	if _, err := newMapStreamService(
		mapConfig,
		nil,
		mapPresenceStoreFixture{},
		mapRevisionWatcherFixture{},
		mapConnectivityWatcherFixture{},
		replicaID,
	); !errors.Is(err, errInvalidMapSessionComposition) {
		t.Fatalf("newMapStreamService(nil) error = %v, want composition error", err)
	}
	service, err := newMapStreamService(
		mapConfig,
		mapSnapshotOpenerFixture{},
		mapPresenceStoreFixture{},
		mapRevisionWatcherFixture{},
		mapConnectivityWatcherFixture{},
		replicaID,
	)
	if err != nil || service == nil {
		t.Fatalf("newMapStreamService() = (%v, %v), want service", service, err)
	}
}

type mapSnapshotStoreFixture struct{}

func (mapSnapshotStoreFixture) Load(
	context.Context,
	control.AuthenticatedNode,
) (mapsession.Snapshot, error) {
	return mapsession.Snapshot{}, errors.New("composition fixture must not be called")
}

type mapSnapshotOpenerFixture struct{}

func (mapSnapshotOpenerFixture) Open(
	context.Context,
	control.AuthenticatedMachine,
	mapsession.Request,
) (mapsession.Snapshot, error) {
	return mapsession.Snapshot{}, errors.New("composition fixture must not be called")
}

type mapEndpointObserverFixture struct{}

func (mapEndpointObserverFixture) ObserveEndpoints(
	context.Context,
	network.Scope,
	node.EndpointObservation,
) (bool, error) {
	return false, errors.New("composition fixture must not be called")
}

type mapPresenceStoreFixture struct{}

func (mapPresenceStoreFixture) AcquirePresence(
	context.Context,
	network.Scope,
	node.PresenceLease,
) (bool, error) {
	return false, errors.New("composition fixture must not be called")
}

func (mapPresenceStoreFixture) RenewPresence(
	context.Context,
	node.PresenceLease,
) (bool, error) {
	return false, errors.New("composition fixture must not be called")
}

type mapConnectivityStoreFixture struct{}

func (mapConnectivityStoreFixture) LoadConnectivity(
	context.Context,
	[]mapsession.ConnectivityKey,
) ([]mapsession.Connectivity, error) {
	return nil, errors.New("composition fixture must not be called")
}

type mapRevisionWatcherFixture struct{}

func (mapRevisionWatcherFixture) WatchNetwork(
	network.ID,
) (<-chan network.RevisionAdvanced, func(), error) {
	return nil, nil, errors.New("composition fixture must not be called")
}

type mapConnectivityWatcherFixture struct{}

func (mapConnectivityWatcherFixture) WatchNetwork(
	network.ID,
) (<-chan mapsession.ConnectivityChanged, func(), error) {
	return nil, nil, errors.New("composition fixture must not be called")
}

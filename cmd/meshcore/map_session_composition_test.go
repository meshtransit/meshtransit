package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

func TestNewMapSessionServiceValidatesComposition(t *testing.T) {
	t.Parallel()

	if _, err := newMapSessionService(nil); !errors.Is(err, errInvalidMapSessionComposition) {
		t.Fatalf("newMapSessionService(nil) error = %v, want composition error", err)
	}
	service, err := newMapSessionService(mapSnapshotStoreFixture{})
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
		replicaID,
	); !errors.Is(err, errInvalidMapSessionComposition) {
		t.Fatalf("newMapStreamService(nil) error = %v, want composition error", err)
	}
	service, err := newMapStreamService(
		mapConfig,
		mapSnapshotOpenerFixture{},
		mapPresenceStoreFixture{},
		mapRevisionWatcherFixture{},
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

type mapPresenceStoreFixture struct{}

func (mapPresenceStoreFixture) ClaimPresence(
	context.Context,
	node.PresenceLease,
) (bool, error) {
	return false, errors.New("composition fixture must not be called")
}

func (mapPresenceStoreFixture) ReleasePresence(
	context.Context,
	node.PresenceLease,
) (bool, error) {
	return false, errors.New("composition fixture must not be called")
}

type mapRevisionWatcherFixture struct{}

func (mapRevisionWatcherFixture) WatchNetwork(
	network.ID,
) (<-chan network.RevisionAdvanced, func(), error) {
	return nil, nil, errors.New("composition fixture must not be called")
}

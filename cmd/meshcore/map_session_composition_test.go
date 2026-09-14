package main

import (
	"context"
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/control/mapsession"
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

type mapSnapshotStoreFixture struct{}

func (mapSnapshotStoreFixture) Load(
	context.Context,
	control.AuthenticatedNode,
) (mapsession.Snapshot, error) {
	return mapsession.Snapshot{}, errors.New("composition fixture must not be called")
}

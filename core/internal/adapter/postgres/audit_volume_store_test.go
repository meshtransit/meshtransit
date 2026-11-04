package postgres

import (
	"context"
	"errors"
	"testing"
)

// auditVolumeDatabase answers the count query with events or err.
type auditVolumeDatabase struct {
	fakeOutboxDatabase
	events int64
	err    error
	query  string
}

func (database *auditVolumeDatabase) QueryRow(_ context.Context, query string, _ ...any) outboxRow {
	database.query = query
	return fakeOutboxRow{scan: func(destinations ...any) error {
		if database.err != nil {
			return database.err
		}
		*destinations[0].(*int64) = database.events
		return nil
	}}
}

func TestAuditVolumeStoreReadsTheDeploymentCount(t *testing.T) {
	t.Parallel()
	database := &auditVolumeDatabase{events: 1379}
	store := &AuditVolumeStore{database: database}
	if events, err := store.DeploymentEvents(t.Context()); err != nil || events != 1379 {
		t.Fatalf("DeploymentEvents() = %d, %v", events, err)
	}
	if database.query != deploymentAuditEventsSQL {
		t.Fatalf("query = %q", database.query)
	}
	database.events = -1
	if _, err := store.DeploymentEvents(t.Context()); !errors.Is(err, ErrInvalidAuditVolumeStore) {
		t.Fatalf("negative count error = %v", err)
	}
	database.err = errors.New("down")
	if _, err := store.DeploymentEvents(t.Context()); err == nil || errors.Is(err, ErrInvalidAuditVolumeStore) {
		t.Fatalf("read error = %v, want the cause", err)
	}
}

func TestAuditVolumeStoreRejectsNonWorkerPools(t *testing.T) {
	t.Parallel()
	if _, err := NewAuditVolumeStore(nil); !errors.Is(err, ErrInvalidAuditVolumeStore) {
		t.Fatalf("nil pool error = %v", err)
	}
	if _, err := NewAuditVolumeStore(&Pool{role: PoolRoleRuntime}); !errors.Is(err, ErrInvalidAuditVolumeStore) {
		t.Fatalf("runtime pool error = %v", err)
	}
}

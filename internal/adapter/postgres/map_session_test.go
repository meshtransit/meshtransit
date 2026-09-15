package postgres

import (
	"errors"
	"testing"
	"time"

	postgresmapsession "github.com/meshtransit/meshtransit/internal/adapter/postgres/mapsession"
)

func TestNewMapSessionStoreRequiresRuntimePool(t *testing.T) {
	options := MapSessionOptions{
		StatementTimeout:   time.Second,
		IdleTimeout:        2 * time.Second,
		PeerCandidateLimit: 100,
	}
	for _, pool := range []*Pool{
		nil,
		{role: PoolRoleWorker},
		{role: PoolRoleRuntime},
	} {
		if _, err := NewMapSessionStore(pool, options); !errors.Is(err, ErrInvalidMapSessionStore) {
			t.Fatalf("NewMapSessionStore() error = %v, want ErrInvalidMapSessionStore", err)
		}
	}
}

func TestNewMapSessionStoreDelegatesValidatedConstruction(t *testing.T) {
	want := &postgresmapsession.Store{}
	wantOptions := MapSessionOptions{
		StatementTimeout:   3 * time.Second,
		IdleTimeout:        5 * time.Second,
		PeerCandidateLimit: 100,
	}
	var gotOptions MapSessionOptions
	pool := &Pool{
		role: PoolRoleRuntime,
		mapSessionStore: func(options postgresmapsession.Options) (*postgresmapsession.Store, error) {
			gotOptions = options
			return want, nil
		},
	}

	got, err := NewMapSessionStore(pool, wantOptions)
	if err != nil {
		t.Fatalf("NewMapSessionStore() error = %v", err)
	}
	if got != want || gotOptions != wantOptions {
		t.Fatalf("NewMapSessionStore() = (%p, %+v), want (%p, %+v)", got, gotOptions, want, wantOptions)
	}
}

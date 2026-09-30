package postgres

import (
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/sessioncontext"
)

func TestAccountSessionStoreReadsDeploymentCapabilities(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	encoded := `{"deployment_id":"01890f00-0000-7000-8000-000000000001",` +
		`"profile":"self_hosted","revision":7}`
	transaction := &fakeAccountSessionTransaction{row: fakeAccountSessionRow{values: []any{&encoded}}}
	store, err := newAccountSessionStore(
		&fakeAccountSessionDatabase{transaction: transaction},
		AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second},
		nil,
	)
	if err != nil {
		t.Fatalf("newAccountSessionStore() error = %v", err)
	}
	session := accountSessionManagementScopeSession(t, now)
	result, err := store.ReadDeploymentCapabilities(t.Context(), session, now)
	if err != nil {
		t.Fatalf("ReadDeploymentCapabilities() error = %v", err)
	}
	if result.DeploymentID != session.DeploymentID() || result.Profile != deployment.ProfileSelfHosted ||
		result.Revision != 7 {
		t.Fatalf("ReadDeploymentCapabilities() result = %+v", result)
	}
	if transaction.commits != 1 || transaction.rollbacks != 0 || len(transaction.arguments) != 11 ||
		transaction.arguments[0] != session.ID().String() || transaction.arguments[10] != now {
		t.Fatalf("transaction commit/rollback/arguments = %d/%d/%v", transaction.commits, transaction.rollbacks, transaction.arguments)
	}
}

func TestAccountSessionStoreDeploymentCapabilitiesConcealsStaleAuthority(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 30, 10, 0, 0, 0, time.UTC)
	transaction := &fakeAccountSessionTransaction{row: fakeAccountSessionRow{values: []any{nil}}}
	store, err := newAccountSessionStore(
		&fakeAccountSessionDatabase{transaction: transaction},
		AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second},
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.ReadDeploymentCapabilities(
		t.Context(),
		accountSessionManagementScopeSession(t, now),
		now,
	)
	if !errors.Is(err, sessioncontext.ErrCapabilitiesUnauthenticated) {
		t.Fatalf("ReadDeploymentCapabilities() error = %v, want ErrCapabilitiesUnauthenticated", err)
	}
	if transaction.commits != 1 || transaction.rollbacks != 0 {
		t.Fatalf("transaction commit/rollback = %d/%d, want 1/0", transaction.commits, transaction.rollbacks)
	}
}

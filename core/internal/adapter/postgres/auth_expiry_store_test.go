package postgres

import (
	"errors"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
)

func TestAuthExpirySetupCleanupFailureRetainsOnlyClosedWorkerClass(t *testing.T) {
	t.Parallel()
	snapshot := authExpirySnapshotFixture(t, false)
	database := newFakeAuthTransactionDatabaseTransaction()
	database.execErrors[configureAuthTransactionSQL] = []error{errors.New("private-detail")}
	database.rollbackErr = errors.New("private-detail")
	store := &AuthExpiryStore{
		database: &fakeAuthTransactionDatabase{transactions: []*fakeAuthTransactionDatabaseTransaction{database}},
		options:  testAuthTransactionOptions(),
	}
	unit, err := store.BeginExpiry(t.Context(), snapshot.DeploymentID())
	if unit != nil || !errors.Is(err, oidcauth.ErrExpiryCleanupFailed) || database.rollbackCalls != 1 ||
		strings.Contains(err.Error(), "private-detail") {
		t.Fatal("failed setup cleanup lost ownership or leaked error text")
	}
}

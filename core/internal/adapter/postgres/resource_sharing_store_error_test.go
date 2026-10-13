package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/sharing"
)

func TestResourceSharingDatabaseErrorNamesTheTakenName(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		constraint string
		want       error
	}{
		{constraint: "imported_resource_network_name_current_uidx", want: sharing.ErrImportedNameTaken},
		{constraint: "imported_resource_access_name_current_uidx", want: sharing.ErrAccessNameTaken},
	} {
		err := resourceSharingDatabaseError(context.Background(),
			&pgconn.PgError{Code: "23505", ConstraintName: test.constraint})
		if !errors.Is(err, test.want) || !errors.Is(err, sharing.ErrConflict) {
			t.Errorf("%s: error = %v, want %v and a conflict", test.constraint, err, test.want)
		}
	}
	other := resourceSharingDatabaseError(context.Background(),
		&pgconn.PgError{Code: "23505", ConstraintName: "trust_contract_share_offer_id_key"})
	if !errors.Is(other, sharing.ErrConflict) || errors.Is(other, sharing.ErrImportedNameTaken) ||
		errors.Is(other, sharing.ErrAccessNameTaken) {
		t.Errorf("other unique violation = %v, want a plain conflict", other)
	}
}

func TestResourceSharingDatabaseErrorNamesTheShareLimit(t *testing.T) {
	t.Parallel()
	err := resourceSharingDatabaseError(context.Background(),
		&pgconn.PgError{Code: "MT012", Message: "the receiving Network has reached its share limit"})
	if !errors.Is(err, sharing.ErrShareLimitReached) || !errors.Is(err, sharing.ErrConflict) {
		t.Fatalf("MT012 = %v, want the share limit and a conflict", err)
	}
	if other := resourceSharingDatabaseError(context.Background(), &pgconn.PgError{Code: "MT001"}); errors.Is(other, sharing.ErrShareLimitReached) {
		t.Fatalf("MT001 = %v, reported as the share limit", other)
	}
}

func TestResourceSharingDatabaseErrorNamesADuplicateShare(t *testing.T) {
	t.Parallel()
	err := resourceSharingDatabaseError(context.Background(),
		&pgconn.PgError{Code: "MT013", Message: "the Device is already shared into the receiving Network"})
	if !errors.Is(err, sharing.ErrAlreadyShared) || !errors.Is(err, sharing.ErrConflict) || errors.Is(err, sharing.ErrShareLimitReached) {
		t.Fatalf("MT013 = %v, want an existing share and a conflict", err)
	}
}

package postgres

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/meshtransit/meshtransit/internal/network/provisioning"
	"github.com/meshtransit/meshtransit/internal/workspace/creation"
	"github.com/meshtransit/meshtransit/internal/workspace/selection"
)

// Provisioning outcomes map by SQLSTATE alone; the message never matters.
func TestProvisioningErrorsMapBySQLState(t *testing.T) {
	t.Parallel()
	pg := func(code string) error { return &pgconn.PgError{Code: code, Message: "any text"} }
	for code, want := range map[string]error{
		"42501": creation.ErrForbidden,
		"MTE01": creation.ErrEntitlementMissing,
		"MTE02": creation.ErrEntitlementExpired,
		"MTL01": creation.ErrDeploymentLimit,
		"MTL02": creation.ErrAccountLimit,
		"23505": creation.ErrConflict,
		"22023": creation.ErrInvalid,
		"40001": creation.ErrUnavailable,
	} {
		if got := workspaceCreationError(pg(code)); !errors.Is(got, want) {
			t.Errorf("Workspace %s = %v, want %v", code, got, want)
		}
	}
	if !errors.Is(workspaceCreationError(pgx.ErrNoRows), creation.ErrForbidden) {
		t.Error("no Workspace row must conceal as forbidden")
	}
	for code, want := range map[string]error{
		"42501": provisioning.ErrForbidden,
		"23P01": provisioning.ErrPrefixOverlap,
		"23505": provisioning.ErrConflict,
		"MTN01": provisioning.ErrPrefixOutsidePool,
		"22023": provisioning.ErrInvalid,
		"40001": provisioning.ErrUnavailable,
	} {
		if got := networkCreationError(pg(code)); !errors.Is(got, want) {
			t.Errorf("Network %s = %v, want %v", code, got, want)
		}
	}
	if !errors.Is(networkCreationError(pgx.ErrNoRows), provisioning.ErrForbidden) {
		t.Error("no Network row must conceal as forbidden")
	}
}

func TestSessionWorkspaceErrorsMapBySQLState(t *testing.T) {
	t.Parallel()
	for code, want := range map[string]error{
		"42501": selection.ErrForbidden,
		"22023": selection.ErrInvalid,
		"P0002": selection.ErrNotAvailable,
		"40001": selection.ErrSessionChanged,
		"57014": selection.ErrUnavailable,
	} {
		if got := sessionWorkspaceError(&pgconn.PgError{Code: code, Message: "any text"}); !errors.Is(got, want) {
			t.Errorf("%s = %v, want %v", code, got, want)
		}
	}
	if !errors.Is(sessionWorkspaceError(pgx.ErrNoRows), selection.ErrForbidden) {
		t.Error("no row must conceal as forbidden")
	}
}

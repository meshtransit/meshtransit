package postgres

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

// TD-SEC-37: each refusal keeps its closed reason; a database failure is not
// a refusal.
func TestInvitationAcceptanceErrorKeepsTheReason(t *testing.T) {
	t.Parallel()
	for code, want := range map[string]oidcauth.InvitationRefusal{
		"MTV06": oidcauth.InvitationRefusalEmailMismatch, "MTV07": oidcauth.InvitationRefusalInviterAuthority,
		"MTV05": oidcauth.InvitationRefusalMemberConflict, "MTV08": oidcauth.InvitationRefusalMemberConflict,
		"P0002": oidcauth.InvitationRefusalNotPending, "23505": oidcauth.InvitationRefusalMemberConflict,
		"42501": oidcauth.InvitationRefusalInvalid, "22023": oidcauth.InvitationRefusalInvalid,
	} {
		var refused oidcauth.InvitationRefusedError
		err := invitationAcceptanceError(&pgconn.PgError{Code: code})
		if !errors.Is(err, oidcauth.ErrInvitationRejected) || !errors.As(err, &refused) || refused.Reason != want {
			t.Errorf("%s: %v, want %s", code, err, want)
		}
	}
	var refused oidcauth.InvitationRefusedError
	if err := invitationAcceptanceError(pgx.ErrNoRows); !errors.As(err, &refused) ||
		refused.Reason != oidcauth.InvitationRefusalNotPending {
		t.Errorf("no rows: %v", err)
	}
	if err := invitationAcceptanceError(&pgconn.PgError{Code: "57014"}); errors.Is(err, oidcauth.ErrInvitationRejected) ||
		!errors.Is(err, oidcauth.ErrInvitationUnavailable) {
		t.Errorf("a cancelled statement: %v, want unavailable", err)
	}
}

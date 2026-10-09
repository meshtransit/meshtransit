package identity_test

import (
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
)

func TestPrincipalIDRoundTrip(t *testing.T) {
	t.Parallel()

	const value = "01890f30-0000-7000-8000-000000000001"
	id, err := identity.ParsePrincipalID(value)
	if err != nil {
		t.Fatalf("ParsePrincipalID() error = %v", err)
	}
	fromBytes, err := identity.NewPrincipalID(id.Bytes())
	if err != nil {
		t.Fatalf("NewPrincipalID() error = %v", err)
	}
	if id != fromBytes || id.String() != value || !id.IsValid() {
		t.Fatalf("principal id round trip = (%q, valid=%t)", id.String(), id.IsValid())
	}
}

func TestPrincipalIDRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	if _, err := identity.ParsePrincipalID("not-an-id"); !errors.Is(err, identity.ErrInvalidPrincipalID) {
		t.Fatalf("ParsePrincipalID() error = %v, want ErrInvalidPrincipalID", err)
	}
	if _, err := identity.NewPrincipalID([16]byte{}); !errors.Is(err, identity.ErrInvalidPrincipalID) {
		t.Fatalf("NewPrincipalID() error = %v, want ErrInvalidPrincipalID", err)
	}
	if (identity.PrincipalID{}).IsValid() {
		t.Fatal("zero PrincipalID is valid")
	}
}

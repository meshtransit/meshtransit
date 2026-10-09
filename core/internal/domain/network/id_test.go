package network_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/network"
)

func TestParseID(t *testing.T) {
	t.Parallel()

	const value = "01890f00-0000-7000-8000-000000000201"
	id, err := network.ParseID(value)
	if err != nil {
		t.Fatalf("ParseID() error = %v", err)
	}
	if id.String() != value || !id.IsValid() {
		t.Fatalf("ParseID() = %q, want valid %q", id.String(), value)
	}
}

func TestParseIDRejectsInvalidValue(t *testing.T) {
	t.Parallel()

	if _, err := network.ParseID("invalid"); !errors.Is(err, network.ErrInvalidID) {
		t.Fatalf("ParseID() error = %v, want ErrInvalidID", err)
	}
	if (network.ID{}).IsValid() {
		t.Fatal("zero ID is valid")
	}
}

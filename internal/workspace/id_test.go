package workspace_test

import (
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestParseID(t *testing.T) {
	t.Parallel()

	const value = "01890f00-0000-7000-8000-000000000101"
	id, err := workspace.ParseID(value)
	if err != nil {
		t.Fatalf("ParseID() error = %v", err)
	}
	if id.String() != value || !id.IsValid() {
		t.Fatalf("ParseID() = %q, want valid %q", id.String(), value)
	}
}

func TestParseIDRejectsInvalidValue(t *testing.T) {
	t.Parallel()

	if _, err := workspace.ParseID("invalid"); !errors.Is(err, workspace.ErrInvalidID) {
		t.Fatalf("ParseID() error = %v, want ErrInvalidID", err)
	}
	if (workspace.ID{}).IsValid() {
		t.Fatal("zero ID is valid")
	}
}

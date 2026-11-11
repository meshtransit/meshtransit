package localapi

import (
	"testing"

	"meshtransit.net/client/internal/daemon"
)

// S4c §4: the profile's identity carries the owner's email meshd kept.
func TestProfileResponseCarriesTheOwnersEmail(t *testing.T) {
	t.Parallel()
	display := daemon.Display{
		Network: "Lab", Workspace: "Acme", Ownership: "member", Owner: "Alice", OwnerEmail: "alice@example.test",
	}
	got := profileResponse{ID: "p1"}.withDisplay(display, true, false)
	if got.Identity == nil || got.Identity.OwnerEmail != "alice@example.test" || got.Identity.Owner != "Alice" {
		t.Fatalf("identity = %+v", got.Identity)
	}
	display.OwnerEmail = ""
	if got := (profileResponse{ID: "p1"}).withDisplay(display, true, false); got.Identity.OwnerEmail != "" {
		t.Fatalf("identity = %+v, want no email", got.Identity)
	}
}

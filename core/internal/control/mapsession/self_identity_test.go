package mapsession

import (
	"errors"
	"strings"
	"testing"
)

func mustSelfIdentity(t *testing.T, workspace string, ownership Ownership, owner string) SelfIdentity {
	t.Helper()
	identity, err := NewSelfIdentity(workspace, ownership, owner)
	if err != nil {
		t.Fatalf("NewSelfIdentity(%q, %d, %q) error = %v", workspace, ownership, owner, err)
	}
	return identity
}

func TestNewSelfIdentityValidatesNames(t *testing.T) {
	t.Parallel()

	member := mustSelfIdentity(t, "Acme", OwnershipMember, "alice@acme.example")
	if !member.Known() || member.WorkspaceName() != "Acme" || member.OwnerName() != "alice@acme.example" {
		t.Fatalf("member identity = %+v", member)
	}
	// An account that is gone leaves a member's Device without a name.
	if gone := mustSelfIdentity(t, "Acme", OwnershipMember, ""); gone.OwnerName() != "" {
		t.Fatalf("gone owner = %+v", gone)
	}
	// A Workspace's Device never carries a person's name.
	if workspace := mustSelfIdentity(t, "Acme", OwnershipWorkspace, "Alice"); workspace.OwnerName() != "" {
		t.Fatalf("workspace identity = %+v", workspace)
	}
	for name, test := range map[string]struct {
		workspace, owner string
		ownership        Ownership
	}{
		"no workspace":      {"", "Alice", OwnershipMember},
		"unknown ownership": {"Acme", "Alice", 0},
		"too long":          {strings.Repeat("a", maxIdentityNameRunes+1), "", OwnershipMember},
		"control":           {"Acme", "Ali\nce", OwnershipMember},
		"padded":            {" Acme", "", OwnershipMember},
		"invalid UTF-8":     {"Acme", "\xff", OwnershipMember},
	} {
		if _, err := NewSelfIdentity(test.workspace, test.ownership, test.owner); !errors.Is(err,
			ErrInvalidSelfIdentity) {
			t.Errorf("%s: error = %v, want ErrInvalidSelfIdentity", name, err)
		}
	}
	if _, err := NewSelfIdentity(strings.Repeat("ạ", maxIdentityNameRunes), OwnershipMember, ""); err != nil {
		t.Errorf("128 runes must fit: %v", err)
	}
	for value, want := range map[string]Ownership{"member": OwnershipMember, "workspace": OwnershipWorkspace} {
		if got, err := ParseOwnership(value); err != nil || got != want {
			t.Errorf("ParseOwnership(%q) = %d, %v", value, got, err)
		}
	}
	if _, err := ParseOwnership("tag"); !errors.Is(err, ErrInvalidSelfIdentity) {
		t.Errorf("ParseOwnership(tag) error = %v", err)
	}
}

func TestSelfIdentityWithWorkspaceName(t *testing.T) {
	t.Parallel()

	identity := mustSelfIdentity(t, "Acme", OwnershipMember, "Alice")
	if renamed := identity.WithWorkspaceName("Acme Labs"); renamed.WorkspaceName() != "Acme Labs" ||
		renamed.OwnerName() != "Alice" {
		t.Fatalf("renamed = %+v", renamed)
	}
	if kept := identity.WithWorkspaceName(""); kept != identity {
		t.Fatalf("an empty name must keep the identity, got %+v", kept)
	}
	if absent := (SelfIdentity{}).WithWorkspaceName("Acme"); absent.Known() {
		t.Fatalf("a session without names must stay without them, got %+v", absent)
	}
}

// Only a session that negotiated self.identity1 keeps the names.
func TestSnapshotWithSelfIdentityCapability(t *testing.T) {
	t.Parallel()

	current, _, _ := authorityDeltaSnapshotsFixture(t)
	params := current.params()
	params.SelfIdentity = mustSelfIdentity(t, "Acme", OwnershipMember, "Alice")
	snapshot, err := NewSnapshot(params)
	if err != nil {
		t.Fatalf("NewSnapshot() error = %v", err)
	}
	if got := snapshot.withSelfIdentityCapability(Request{}).SelfIdentity(); got.Known() {
		t.Fatalf("without the capability = %+v", got)
	}
	if got := snapshot.withSelfIdentityCapability(Request{}.WithSelfIdentity()).SelfIdentity(); !got.Known() {
		t.Fatalf("with the capability = %+v", got)
	}
	if rebuilt, err := NewSnapshot(snapshot.params()); err != nil || rebuilt.SelfIdentity() != params.SelfIdentity {
		t.Fatalf("params() must carry the names: %+v, %v", rebuilt.SelfIdentity(), err)
	}
}

// S4b §3.3 (Q9): a change of the names alone, with the revision, is a
// delta that replaces self, not a full snapshot.
func TestNewAuthorityDeltaCarriesSelfIdentityChange(t *testing.T) {
	t.Parallel()

	base, _, _ := authorityDeltaSnapshotsFixture(t)
	withIdentity := func(identity SelfIdentity, revision int64) Snapshot {
		t.Helper()
		params := base.params()
		params.SelfIdentity, params.NetworkRevision = identity, revision
		snapshot, err := NewSnapshot(params)
		if err != nil {
			t.Fatalf("NewSnapshot() error = %v", err)
		}
		return snapshot
	}
	before := mustSelfIdentity(t, "Acme", OwnershipMember, "Alice")
	current := withIdentity(before, base.NetworkRevision())
	renamed := withIdentity(mustSelfIdentity(t, "Acme Labs", OwnershipMember, "Alice"), base.NetworkRevision()+1)
	delta, err := NewAuthorityDelta(current, renamed)
	if err != nil || !delta.IsValid() || !delta.SelfChanged() || len(delta.ChangedPeers()) != 0 {
		t.Fatalf("NewAuthorityDelta(renamed) = %+v, %v; want self replaced", delta, err)
	}
	same := withIdentity(before, base.NetworkRevision()+1)
	if _, err := NewAuthorityDelta(current, same); !errors.Is(err, ErrInvalidAuthorityDelta) {
		t.Fatalf("an unchanged map must still not be a delta: %v", err)
	}
}

package networkmap

import (
	"strings"
	"testing"
)

// An identity the map cannot show is dropped on publication, never the map.
func TestValidateAndCloneDropsAnInvalidIdentity(t *testing.T) {
	t.Parallel()
	snapshot, now := aliasTestSnapshot()
	snapshot.Peers = nil
	snapshot.Identity = &Identity{Network: "Lab", Workspace: "Acme", Ownership: OwnershipMember, Owner: "Alice"}
	cloned, err := ValidateAndClone(snapshot, now)
	if err != nil || cloned.Identity == nil || cloned.Identity == snapshot.Identity || cloned.Identity.Owner != "Alice" {
		t.Fatalf("ValidateAndClone() = %+v, %v; want a copy of the identity", cloned.Identity, err)
	}
	snapshot.Identity = &Identity{Network: "Lab", Workspace: "Acme", Ownership: "robot"}
	if cloned, err := ValidateAndClone(snapshot, now); err != nil || cloned.Identity != nil {
		t.Fatalf("ValidateAndClone(invalid) = %+v, %v; want the map without it", cloned.Identity, err)
	}
}

// CheckEmail is Core's displayemail.Valid (S4c §3.1); this table is Core's,
// so the two rules cannot drift apart unseen.
func TestCheckEmail(t *testing.T) {
	t.Parallel()
	for email, want := range map[string]bool{
		"person@example.test":                 true,
		"a.b+c@example.test":                  true,
		"":                                    false,
		"a@b":                                 false,
		"no-at.example.test":                  false,
		"two@at@example.test":                 false,
		"@example.test":                       false,
		"user@":                               false,
		"user@localhost":                      false,
		"user@exämple.test":                   false,
		"user\u00a0x@example.test":            false,
		"user\u202e@example.test":             false,
		"user<x@example.test":                 false,
		"user>x@example.test":                 false,
		"user\"x@example.test":                false,
		"user x@example.test":                 false,
		"user\tx@example.test":                false,
		strings.Repeat("a", 240) + "@ex.test": true,
		strings.Repeat("a", 250) + "@ex.test": false,
	} {
		if got := CheckEmail(email); got != want {
			t.Errorf("CheckEmail(%q) = %t, want %t", email, got, want)
		}
	}
}

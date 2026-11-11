package networkmap

import "testing"

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

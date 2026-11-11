package mtcpclient

import (
	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/networkmap"
)

// selfIdentityCapability is self.identity1: the node takes its account's
// names on its own entry (mtcp-v1 §7.13). A Kubernetes gateway never
// declares it.
const selfIdentityCapability = "self.identity1"

// identity is the names of the node's account its own entry carries; nil
// when absent or malformed: they are for display only and never cost the
// node its map.
func (state *mapState) identity() *networkmap.Identity {
	named := state.self.GetIdentity()
	if named == nil {
		return nil
	}
	identity := &networkmap.Identity{
		Network: named.GetNetworkDisplayName(), Workspace: named.GetWorkspaceDisplayName(),
		Owner: named.GetOwnerDisplayName(),
	}
	switch named.GetOwnership() {
	case mtcpv1.SelfIdentity_MEMBER:
		identity.Ownership = networkmap.OwnershipMember
	case mtcpv1.SelfIdentity_WORKSPACE:
		identity.Ownership = networkmap.OwnershipWorkspace
	default:
		return nil
	}
	if networkmap.CheckIdentity(identity) != nil {
		return nil
	}
	// The owner's email (S4c §4): absent from an older Core. A bad one, or
	// one on a Workspace's Device, is dropped: it reads as "the account has
	// none" (clearing what meshd kept) and keeps the names.
	if named.OwnerEmail != nil {
		identity.EmailKnown = true
		if email := named.GetOwnerEmail(); identity.Ownership == networkmap.OwnershipMember &&
			networkmap.CheckEmail(email) {
			identity.Email = email
		}
	}
	return identity
}

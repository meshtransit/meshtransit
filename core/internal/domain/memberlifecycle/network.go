package memberlifecycle

import (
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// Network membership lets a Workspace member enroll Devices into a Network
// and receive Devices handed over in it. network.member.manage adds members
// to one Network and removes them, handling the member's Devices there as a
// Workspace removal does.

const (
	// MaximumNetworkAdditions bounds the members one addition names.
	MaximumNetworkAdditions = 150
	// MaximumNetworkMemberPage bounds one page of a Network's members.
	MaximumNetworkMemberPage = 200
	// DefaultNetworkMemberPage is the page size when none is asked for.
	DefaultNetworkMemberPage = 100
)

// NetworkMembership is one membership of a Network.
type NetworkMembership struct {
	MembershipID publicid.ID
	PrincipalID  publicid.ID
	State        string
	Version      int64
	AddedAt      time.Time
}

// NetworkMember is a Workspace member and their membership of the Network,
// nil when they are not a member.
type NetworkMember struct {
	PrincipalID    publicid.ID
	DisplayName    string
	WorkspaceState string
	Owner          bool
	Membership     *NetworkMembership
}

// NetworkMemberPage is one page of members ordered by principal ID.
type NetworkMemberPage struct {
	Members   []NetworkMember
	CanManage bool
	HasMore   bool
}

// NetworkMemberQuery asks for one page after a principal ID.
type NetworkMemberQuery struct {
	Session accountsession.Session
	Scope   network.Scope
	After   publicid.ID
	Limit   int
}

// IsValid reports a complete, bounded query.
func (query NetworkMemberQuery) IsValid() bool {
	return query.Session.IsValid() && query.Scope.IsValid() && query.Limit >= 1 &&
		query.Limit <= MaximumNetworkMemberPage
}

// NetworkAddition adds Workspace members to one Network.
type NetworkAddition struct {
	Session       accountsession.Session
	Scope         network.Scope
	MemberIDs     []publicid.ID
	CorrelationID publicid.ID
}

// IsValid reports a complete addition naming each member once.
func (addition NetworkAddition) IsValid() bool {
	if !addition.Session.IsValid() || !addition.Scope.IsValid() || !addition.CorrelationID.IsValid() ||
		len(addition.MemberIDs) == 0 ||
		len(addition.MemberIDs) > MaximumNetworkAdditions {
		return false
	}
	seen := make(map[publicid.ID]bool, len(addition.MemberIDs))
	for _, member := range addition.MemberIDs {
		if !member.IsValid() || seen[member] {
			return false
		}
		seen[member] = true
	}
	return true
}

// NetworkAdditionResult lists the memberships created and the members who
// were already in the Network.
type NetworkAdditionResult struct {
	NetworkRevision int64
	Added           []NetworkMembership
	Unchanged       []publicid.ID
}

// NetworkRemoval removes one member from one Network.
type NetworkRemoval struct {
	Session       accountsession.Session
	Scope         network.Scope
	MemberID      publicid.ID
	Reason        string
	Devices       []DevicePlan
	CorrelationID publicid.ID
}

// IsValid reports a complete removal with a reason and a bounded plan that
// names each Device once and never hands one to the member.
func (removal NetworkRemoval) IsValid() bool {
	if !removal.Session.IsValid() || !removal.Scope.IsValid() || !removal.MemberID.IsValid() ||
		!ValidReason(removal.Reason) || !removal.CorrelationID.IsValid() ||
		len(removal.Devices) > MaximumPlanDevices {
		return false
	}
	seen := make(map[node.ID]bool, len(removal.Devices))
	for _, plan := range removal.Devices {
		if !plan.IsValid() || seen[plan.DeviceID] || plan.NewOwnerID == removal.MemberID {
			return false
		}
		seen[plan.DeviceID] = true
	}
	return true
}

// NetworkRemovalResult is the membership before and after the removal, with
// its effects in the Network.
type NetworkRemovalResult struct {
	Before             NetworkMembership
	After              NetworkMembership
	Devices            []RemovedDevice
	HandoversCancelled int
	KeysRevoked        int
	RolesRevoked       int
	Network            AdvancedNetwork
}

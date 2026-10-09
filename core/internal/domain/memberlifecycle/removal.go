package memberlifecycle

import (
	"errors"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

var (
	// ErrPlan reports a plan naming a Device the member does not own in the
	// Workspace, or a Device that cannot take the chosen action.
	ErrPlan = errors.New("member lifecycle: the plan does not fit the member's Devices")
	// ErrNewOwner reports a new owner who is not an active member of the
	// Device's Network.
	ErrNewOwner = errors.New("member lifecycle: the new owner cannot receive the Device")
)

// MaximumPlanDevices bounds the Devices one removal names.
const MaximumPlanDevices = 250

// DeviceAction is what a removal does with one of the member's Devices.
type DeviceAction string

// Device actions. A Device the plan does not name is revoked.
const (
	DeviceTransferWorkspace DeviceAction = "transfer_workspace"
	DeviceTransferMember    DeviceAction = "transfer_member"
	DeviceRevoke            DeviceAction = "revoke"
)

// DevicePlan is the choice for one Device.
type DevicePlan struct {
	DeviceID   node.ID
	Action     DeviceAction
	NewOwnerID publicid.ID
}

// IsValid reports a known action whose new owner is set exactly for a
// handover.
func (plan DevicePlan) IsValid() bool {
	switch plan.Action {
	case DeviceTransferWorkspace, DeviceRevoke:
		return plan.DeviceID.IsValid() && plan.NewOwnerID == (publicid.ID{})
	case DeviceTransferMember:
		return plan.DeviceID.IsValid() && plan.NewOwnerID.IsValid()
	default:
		return false
	}
}

// Removal is one validated member removal.
type Removal struct {
	Session       accountsession.Session
	WorkspaceID   workspace.ID
	MemberID      publicid.ID
	Reason        string
	Devices       []DevicePlan
	CorrelationID publicid.ID
	EvaluatedAt   time.Time
}

// IsValid reports a complete removal with a reason and a bounded plan that
// names each Device once.
func (removal Removal) IsValid() bool {
	if !removal.Session.IsValid() || !removal.WorkspaceID.IsValid() || !removal.MemberID.IsValid() ||
		!ValidReason(removal.Reason) || !removal.CorrelationID.IsValid() || removal.EvaluatedAt.IsZero() ||
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

// RemovedDevice is one of the member's Devices and what the removal did.
type RemovedDevice struct {
	DeviceID  node.ID
	NetworkID network.ID
	Hostname  string
	Action    DeviceAction
	State     string
}

// RemovalResult is the member before and after the removal, with its
// effects.
type RemovalResult struct {
	Before             Member
	After              Member
	Devices            []RemovedDevice
	HandoversCancelled int
	KeysRevoked        int
	GroupsLeft         int
	RolesRevoked       int
	SessionsEnded      int
	Networks           []AdvancedNetwork
}

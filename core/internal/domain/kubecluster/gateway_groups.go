package kubecluster

import "time"

// A gateway's groups as its last RBAC check left them (K1d d3, mtcp-v1
// §6.11): shown to people, never a security decision.
const (
	GroupStateEnabled  = "enabled"
	GroupStateDisabled = "disabled"
	GroupStatePending  = "pending"

	GroupReasonNone             = "none"
	GroupReasonNotChecked       = "not_checked"
	GroupReasonCheckStale       = "check_stale"
	GroupReasonAPIError         = "api_error"
	GroupReasonRBACExceeds      = "rbac_exceeds"
	GroupReasonImpersonationOff = "impersonation_off"
)

// How a replica's group report reads: current, stale (over 20 minutes
// old), unsupported (its meshgw does not report) or none yet.
const (
	GroupReportCurrent     = "current"
	GroupReportStale       = "stale"
	GroupReportUnsupported = "unsupported"
	GroupReportNone        = "none"
)

// GatewayGroupStatus is one group of a gateway report.
type GatewayGroupStatus struct {
	Group      string `json:"group"`
	Privileged bool   `json:"privileged"`
	State      string `json:"state"`
	Reason     string `json:"reason"`
}

// GatewayGroupReport is what a gateway session reports; Supported false
// records a session that does not report (an older meshgw).
type GatewayGroupReport struct {
	Supported bool
	Groups    []GatewayGroupStatus
	Truncated bool
	CheckedAt time.Time
	// ReceivedAt is when Core took it from the gateway: an older report
	// never replaces a newer one another Core replica wrote.
	ReceivedAt time.Time
}

// ReplicaGroups is a replica's latest report as people read it.
type ReplicaGroups struct {
	Status     string
	ReportedAt time.Time
	CheckedAt  time.Time
	Truncated  bool
	Items      []GatewayGroupStatus
}

// ValidGatewayGroupStatus reports a state and reason that fit together, as
// mtcp-v1 §6.11 has them.
func ValidGatewayGroupStatus(status GatewayGroupStatus) bool {
	if !ValidKubernetesGroup(status.Group) {
		return false
	}
	switch status.State {
	case GroupStateEnabled:
		return status.Reason == GroupReasonNone || status.Reason == GroupReasonImpersonationOff && status.Privileged
	case GroupStatePending:
		return status.Reason == GroupReasonNotChecked
	case GroupStateDisabled:
		switch status.Reason {
		case GroupReasonNotChecked, GroupReasonCheckStale, GroupReasonAPIError, GroupReasonRBACExceeds:
			return true
		}
	}
	return false
}

// ValidReplicaGroups reports a report as the database may hold it.
func ValidReplicaGroups(groups ReplicaGroups) bool {
	if len(groups.Items) > MaximumClusterKubernetesGroups {
		return false
	}
	seen := make(map[string]struct{}, len(groups.Items))
	for _, item := range groups.Items {
		if _, twice := seen[item.Group]; twice || !ValidGatewayGroupStatus(item) {
			return false
		}
		seen[item.Group] = struct{}{}
	}
	switch groups.Status {
	case GroupReportNone:
		return groups.ReportedAt.IsZero() && groups.CheckedAt.IsZero() && !groups.Truncated && len(groups.Items) == 0
	case GroupReportUnsupported:
		return !groups.ReportedAt.IsZero() && groups.CheckedAt.IsZero() && !groups.Truncated &&
			len(groups.Items) == 0
	case GroupReportCurrent, GroupReportStale:
		return !groups.ReportedAt.IsZero()
	}
	return false
}

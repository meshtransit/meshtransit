package mtcp

import (
	"errors"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

// gateway.groups1 bounds (mtcp-v1 §6.11).
const (
	// GatewayGroupReportMaximum bounds the groups of one report, as many as
	// the rules of a cluster may grant.
	GatewayGroupReportMaximum = 64
	gatewayGroupNameMaximum   = 63
)

// ErrGatewayGroupReport reports a GatewayGroupReport that breaks §6.11.
var ErrGatewayGroupReport = errors.New("mtcp: invalid gateway group report")

// ValidateGatewayGroupReport checks a report as Core takes it: at most 64
// distinct groups named as RFC 1123 labels, each with a known state and a
// reason that fits it.
func ValidateGatewayGroupReport(report *mtcpv1.GatewayGroupReport) error {
	groups := report.GetGroups()
	if len(groups) > GatewayGroupReportMaximum || report.GetCheckedAtMs() < 0 {
		return ErrGatewayGroupReport
	}
	seen := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		name := group.GetGroup()
		if _, twice := seen[name]; twice || !validGroupName(name) || !validGroupVerdict(group) {
			return ErrGatewayGroupReport
		}
		seen[name] = struct{}{}
	}
	return nil
}

// validGroupVerdict pairs states and reasons: an enabled group has none, or
// lost impersonation if privileged; a pending one was not checked; a
// disabled one says why.
func validGroupVerdict(group *mtcpv1.GatewayGroupStatus) bool {
	reason := group.GetReason()
	switch group.GetState() {
	case mtcpv1.GatewayGroupStatus_ENABLED:
		return reason == mtcpv1.GatewayGroupStatus_NONE ||
			reason == mtcpv1.GatewayGroupStatus_IMPERSONATION_OFF && group.GetPrivileged()
	case mtcpv1.GatewayGroupStatus_PENDING:
		return reason == mtcpv1.GatewayGroupStatus_NOT_CHECKED
	case mtcpv1.GatewayGroupStatus_DISABLED:
		return reason == mtcpv1.GatewayGroupStatus_CHECK_STALE || reason == mtcpv1.GatewayGroupStatus_API_ERROR ||
			reason == mtcpv1.GatewayGroupStatus_RBAC_EXCEEDS || reason == mtcpv1.GatewayGroupStatus_NOT_CHECKED
	default:
		return false
	}
}

// validGroupName reports an RFC 1123 DNS label, as Core names Kubernetes
// groups.
func validGroupName(name string) bool {
	if name == "" || len(name) > gatewayGroupNameMaximum {
		return false
	}
	for index := range len(name) {
		character := name[index]
		alphanumeric := character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
		if !alphanumeric && (character != '-' || index == 0 || index == len(name)-1) {
			return false
		}
	}
	return true
}

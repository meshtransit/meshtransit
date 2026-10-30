package meshgw

import (
	"sync"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/rbaccheck"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// groupReports turns rbaccheck's verdicts into the gateway's group report
// for Core (gateway.groups1, mtcp-v1 §6.11). The control client is built
// before the checker: report returns nil until bind.
type groupReports struct {
	mu       sync.Mutex
	groups   []rbaccheck.Group
	verdict  func(string) rbaccheck.Verdict
	lastPass func() time.Time
	// passthrough: the gateway serves no groups, and says so (review d3c
	// M1): an empty report, not silence that reads as an old meshgw.
	passthrough bool
}

// bind starts reporting groups as verdict judges them; lastPass is when
// the checker last ended a whole pass.
func (reports *groupReports) bind(groups []rbaccheck.Group, verdict func(string) rbaccheck.Verdict,
	lastPass func() time.Time) {
	if reports == nil {
		return
	}
	reports.mu.Lock()
	defer reports.mu.Unlock()
	reports.groups, reports.verdict, reports.lastPass = groups, verdict, lastPass
}

// report is the groups' latest verdicts, at most 64 (the rest truncated),
// with reason codes only: never the API server's own error text.
func (reports *groupReports) report() *mtcpv1.GatewayGroupReport {
	reports.mu.Lock()
	groups, verdict, lastPass, passthrough := reports.groups, reports.verdict, reports.lastPass,
		reports.passthrough
	reports.mu.Unlock()
	if passthrough {
		return &mtcpv1.GatewayGroupReport{}
	}
	if verdict == nil {
		return nil
	}
	report := &mtcpv1.GatewayGroupReport{Truncated: len(groups) > sharedmtcp.GatewayGroupReportMaximum}
	for _, group := range groups[:min(len(groups), sharedmtcp.GatewayGroupReportMaximum)] {
		report.Groups = append(report.Groups, reportedGroup(group, verdict(group.Name)))
	}
	if passed := lastPass(); !passed.IsZero() {
		report.CheckedAtMs = passed.UnixMilli()
	}
	return report
}

// reportedGroup maps a verdict onto §6.11's states and reasons.
func reportedGroup(group rbaccheck.Group, verdict rbaccheck.Verdict) *mtcpv1.GatewayGroupStatus {
	status := &mtcpv1.GatewayGroupStatus{Group: group.Name, Privileged: group.Privileged,
		State: mtcpv1.GatewayGroupStatus_DISABLED, Reason: mtcpv1.GatewayGroupStatus_NOT_CHECKED}
	switch {
	case verdict.Enabled && verdict.Code == rbaccheck.CodeImpersonationOff && group.Privileged:
		status.State, status.Reason = mtcpv1.GatewayGroupStatus_ENABLED, mtcpv1.GatewayGroupStatus_IMPERSONATION_OFF
	case verdict.Enabled:
		status.State, status.Reason = mtcpv1.GatewayGroupStatus_ENABLED, mtcpv1.GatewayGroupStatus_NONE
	case verdict.CheckedAt.IsZero() && verdict.Code == rbaccheck.CodeNotChecked:
		status.State = mtcpv1.GatewayGroupStatus_PENDING
	case verdict.Code == rbaccheck.CodeCheckStale:
		status.Reason = mtcpv1.GatewayGroupStatus_CHECK_STALE
	case verdict.Code == rbaccheck.CodeAPIError:
		status.Reason = mtcpv1.GatewayGroupStatus_API_ERROR
	case verdict.Code == rbaccheck.CodeRBACExceeds:
		status.Reason = mtcpv1.GatewayGroupStatus_RBAC_EXCEEDS
	}
	return status
}

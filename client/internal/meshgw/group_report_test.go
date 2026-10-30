package meshgw

import (
	"fmt"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/rbaccheck"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// What rbaccheck made of each group, as Core takes it: reason codes only,
// never the API server's error text.
func TestGroupReportsMapVerdicts(t *testing.T) {
	t.Parallel()
	checked := time.Unix(1_800_000_000, 0)
	groups := []rbaccheck.Group{
		{Name: "view"}, {Name: "sre", Privileged: true, AllowImpersonation: true}, {Name: "edit"},
		{Name: "ops"}, {Name: "dev"}, {Name: "late"},
	}
	verdicts := map[string]rbaccheck.Verdict{
		"view": {Enabled: true, CheckedAt: checked},
		"sre": {Enabled: true, Code: rbaccheck.CodeImpersonationOff, Reason: "may impersonate users",
			CheckedAt: checked.Add(time.Second)},
		"edit": {Code: rbaccheck.CodeRBACExceeds, Reason: "may create pods", CheckedAt: checked},
		"ops":  {Code: rbaccheck.CodeAPIError, Detail: "dial tcp 10.0.0.1:443: refused", CheckedAt: checked},
		"dev":  {Code: rbaccheck.CodeNotChecked},
		"late": {Code: rbaccheck.CodeCheckStale, CheckedAt: checked.Add(-time.Hour)},
	}
	reports := &groupReports{}
	if reports.report() != nil {
		t.Fatal("a report before the checker was bound")
	}
	passed := checked.Add(2 * time.Minute)
	reports.bind(groups, func(group string) rbaccheck.Verdict { return verdicts[group] },
		func() time.Time { return passed })
	report := reports.report()
	if err := sharedmtcp.ValidateGatewayGroupReport(report); err != nil || report.GetTruncated() {
		t.Fatalf("report %v: %v", report, err)
	}
	want := map[string][2]int32{
		"view": {int32(mtcpv1.GatewayGroupStatus_ENABLED), int32(mtcpv1.GatewayGroupStatus_NONE)},
		"sre":  {int32(mtcpv1.GatewayGroupStatus_ENABLED), int32(mtcpv1.GatewayGroupStatus_IMPERSONATION_OFF)},
		"edit": {int32(mtcpv1.GatewayGroupStatus_DISABLED), int32(mtcpv1.GatewayGroupStatus_RBAC_EXCEEDS)},
		"ops":  {int32(mtcpv1.GatewayGroupStatus_DISABLED), int32(mtcpv1.GatewayGroupStatus_API_ERROR)},
		"dev":  {int32(mtcpv1.GatewayGroupStatus_PENDING), int32(mtcpv1.GatewayGroupStatus_NOT_CHECKED)},
		"late": {int32(mtcpv1.GatewayGroupStatus_DISABLED), int32(mtcpv1.GatewayGroupStatus_CHECK_STALE)},
	}
	for _, group := range report.GetGroups() {
		if got := [2]int32{int32(group.GetState()), int32(group.GetReason())}; got != want[group.GetGroup()] {
			t.Errorf("%s: %v, want %v", group.GetGroup(), got, want[group.GetGroup()])
		}
	}
	// The checker's last whole pass.
	if report.GetCheckedAtMs() != passed.UnixMilli() {
		t.Fatalf("checked at %d", report.GetCheckedAtMs())
	}
	// More than 64 groups: the first 64, truncated.
	many := make([]rbaccheck.Group, 70)
	for index := range many {
		many[index] = rbaccheck.Group{Name: fmt.Sprintf("g%d", index)}
	}
	reports.bind(many, func(string) rbaccheck.Verdict { return rbaccheck.Verdict{Enabled: true} },
		func() time.Time { return time.Time{} })
	if report := reports.report(); len(report.GetGroups()) != 64 || !report.GetTruncated() ||
		sharedmtcp.ValidateGatewayGroupReport(report) != nil {
		t.Fatalf("70 groups: %d sent, truncated %t", len(report.GetGroups()), report.GetTruncated())
	}
}

// A passthrough gateway serves no groups and says so with an empty report.
func TestGroupReportsOfAPassthroughGateway(t *testing.T) {
	t.Parallel()
	report := (&groupReports{passthrough: true}).report()
	if report == nil || len(report.GetGroups()) != 0 || sharedmtcp.ValidateGatewayGroupReport(report) != nil {
		t.Fatalf("passthrough report %v", report)
	}
}

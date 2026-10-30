package mtcpclient

import (
	"errors"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
)

func groupReportOf(state mtcpv1.GatewayGroupStatus_State, reason mtcpv1.GatewayGroupStatus_Reason) *mtcpv1.GatewayGroupReport {
	return &mtcpv1.GatewayGroupReport{Groups: []*mtcpv1.GatewayGroupStatus{{Group: "view", State: state,
		Reason: reason}}}
}

// A gateway sends its report at once, again when it changes, an unchanged
// one every 10 minutes, and never one that breaks §6.11 (Core would end the
// session).
func TestSendGroupReportCadence(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_800_000_000, 0)
	enabled := groupReportOf(mtcpv1.GatewayGroupStatus_ENABLED, mtcpv1.GatewayGroupStatus_NONE)
	disabled := groupReportOf(mtcpv1.GatewayGroupStatus_DISABLED, mtcpv1.GatewayGroupStatus_RBAC_EXCEEDS)
	invalid := groupReportOf(mtcpv1.GatewayGroupStatus_ENABLED, mtcpv1.GatewayGroupStatus_RBAC_EXCEEDS)
	current := enabled
	conn := &countingConn{}
	s := tokenSession(t, conn, start)
	s.groups = true
	run := &sessionRun{s: s, stream: &netmapStream{client: &Client{groupReport: func() *mtcpv1.GatewayGroupReport {
		return current
	}}}}
	step := func(at time.Duration, report *mtcpv1.GatewayGroupReport, writes int) {
		t.Helper()
		current = report
		if err := run.sendGroupReport(start.Add(at)); err != nil || conn.writes != writes {
			t.Fatalf("at %v: %d writes, %v; want %d", at, conn.writes, err, writes)
		}
	}
	step(0, enabled, 1)
	step(groupReportBeat, enabled, 1)
	step(2*groupReportBeat, disabled, 2)
	step(3*groupReportBeat, invalid, 2)
	step(4*groupReportBeat, nil, 2)
	step(2*groupReportBeat+groupReportResend, disabled, 3)

	// A session without gateway.groups1 sends nothing.
	s.groups = false
	step(time.Hour, enabled, 3)

	// A failed write ends the session.
	s.groups, conn.err = true, errors.New("closed")
	if err := run.sendGroupReport(start.Add(2 * time.Hour)); err == nil {
		t.Fatal("a failed write was not reported")
	}
}

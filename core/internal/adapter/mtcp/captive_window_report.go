package mtcp

import (
	"context"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/captivewindow"
)

const (
	// captiveReportInterval spaces the reports taken from one session: a
	// node reports windows after they closed, at most a few a day.
	captiveReportInterval = 10 * time.Second
	captiveRecordTimeout  = 5 * time.Second
)

var captiveWindowEnds = map[mtcpv1.CaptiveWindow_End]captivewindow.End{
	mtcpv1.CaptiveWindow_EXPIRED:     captivewindow.EndExpired,
	mtcpv1.CaptiveWindow_CLOSED:      captivewindow.EndClosed,
	mtcpv1.CaptiveWindow_TUNNEL_BACK: captivewindow.EndTunnelBack,
}

// captiveWindows records the captive portal windows of a CaptiveWindowReport
// under the Device of the session's map (captive.audit1). A report sooner
// than captiveReportInterval after the last is dropped; the node reports
// again on its next session. A window whose times Core cannot take (a
// node's clock ahead of Core's, or a window too old) or listed twice is left
// out, and one the database refuses is logged: none is the session's fault.
func (conversation *conversation) captiveWindows(ctx context.Context, report *mtcpv1.CaptiveWindowReport) error {
	if !conversation.session.Supports("captive.audit1") {
		return Violation(mtcpv1.Error_INVALID, "captive window report without captive.audit1")
	}
	windows := report.GetWindows()
	if len(windows) == 0 || len(windows) > captivewindow.MaximumPerReport {
		return Violation(mtcpv1.Error_INVALID, "invalid captive window report")
	}
	now := conversation.application.now()
	converted := make([]captivewindow.Window, 0, len(windows))
	seen := make(map[string]bool, len(windows))
	for _, window := range windows {
		end, known := captiveWindowEnds[window.GetEnd()]
		item := captivewindow.Window{
			ID: window.GetWindowId(), OpenedAt: time.UnixMilli(window.GetOpenedMs()).UTC(),
			ClosedAt: time.UnixMilli(window.GetClosedMs()).UTC(), End: end,
		}
		if !known || !captivewindow.ValidID(item.ID) {
			return Violation(mtcpv1.Error_INVALID, "invalid captive window")
		}
		if seen[item.ID] {
			continue // a node may see one window end twice; the first counts
		}
		seen[item.ID] = true
		if item.Validate(now) != nil {
			conversation.application.options.Logger.WarnContext(ctx, "mtcp captive window times not taken",
				"window", item.ID)
			continue
		}
		converted = append(converted, item)
	}
	recorder := conversation.application.options.CaptiveWindows
	snapshot, mapped := conversation.sink.snapshot()
	if recorder == nil || !mapped || len(converted) == 0 || now.Sub(conversation.lastCaptive) < captiveReportInterval {
		return nil
	}
	conversation.lastCaptive = now
	for _, window := range converted {
		recordCtx, cancel := context.WithTimeout(ctx, captiveRecordTimeout)
		outcome, err := recorder.Record(recordCtx, snapshot.Scope(), snapshot.NodeID(), window)
		cancel()
		if err != nil {
			conversation.application.options.Logger.WarnContext(ctx, "mtcp captive window not recorded", "error", err)
			continue
		}
		if outcome == captivewindow.OutcomeLimited {
			conversation.application.options.Logger.WarnContext(ctx, "mtcp captive windows over the daily budget",
				"device", snapshot.NodeID().String())
		}
	}
	return nil
}

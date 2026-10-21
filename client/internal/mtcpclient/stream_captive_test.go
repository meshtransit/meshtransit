package mtcpclient

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// A host using exits declares captive.audit1 and, once mapped, reports the
// captive portal windows that closed, telling the daemon which it sent.
func TestStreamNetmapReportsCaptiveWindows(t *testing.T) {
	t.Parallel()
	reports := make(chan *mtcpv1.CaptiveWindowReport, 1)
	core := newStreamCore(t, func(core *streamCore, s *coreSession, _ int32) {
		core.keyUpdate(s)
		_ = s.send(sharedmtcp.MessageMapSnapshot, core.snapshot(1))
		if report, ok := core.expect(s, sharedmtcp.MessageCaptiveWindowReport).(*mtcpv1.CaptiveWindowReport); ok {
			reports <- report
		}
		_ = s.send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_REVOKED})
		answerPings(s)
	})
	core.extra = []string{"routes.exit.v1", "routes.selection1", "captive.audit1"}
	material, options := core.options(t)
	closed := time.Now().Add(-time.Minute).Truncate(time.Millisecond)
	window := controlplane.CaptiveWindow{
		ID: strings.Repeat("ab", 16), Opened: closed.Add(-2 * time.Minute), Closed: closed,
		End: controlplane.CaptiveWindowTunnelBack,
	}
	var mu sync.Mutex
	var sent []string
	options.EnableExits = true
	options.CaptiveWindows = func() []controlplane.CaptiveWindow {
		// One without an end, and the same window twice, are left out.
		return []controlplane.CaptiveWindow{window, {ID: strings.Repeat("cd", 16), Closed: closed}, window}
	}
	options.CaptiveWindowsSent = func(ids []string) {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, ids...)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	_ = core.client().StreamNetmap(ctx, core.origin(), material, options,
		func(context.Context, networkmap.Snapshot) error { return nil })
	if !slices.ContainsFunc(core.hello, func(hello *mtcpv1.ClientHello) bool {
		return slices.Contains(hello.GetCapabilities(), "captive.audit1")
	}) {
		t.Fatal("the map stream did not declare captive.audit1")
	}
	select {
	case report := <-reports:
		windows := report.GetWindows()
		if len(windows) != 1 || windows[0].GetWindowId() != window.ID ||
			windows[0].GetOpenedMs() != window.Opened.UnixMilli() || windows[0].GetClosedMs() != closed.UnixMilli() ||
			windows[0].GetEnd() != mtcpv1.CaptiveWindow_TUNNEL_BACK {
			t.Fatalf("captive window report %v", report)
		}
	default:
		t.Fatal("no captive window report reached Core")
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(sent, []string{window.ID}) {
		t.Fatalf("told the daemon it sent %v", sent)
	}
}

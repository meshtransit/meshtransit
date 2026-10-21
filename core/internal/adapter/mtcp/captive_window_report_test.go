package mtcp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/captivewindow"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

type fakeCaptiveRecorder struct {
	mu      sync.Mutex
	devices []node.ID
	windows []captivewindow.Window
}

func (f *fakeCaptiveRecorder) Record(_ context.Context, _ network.Scope, device node.ID,
	window captivewindow.Window) (captivewindow.Outcome, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devices, f.windows = append(f.devices, device), append(f.windows, window)
	return captivewindow.OutcomeAudited, nil
}

// A Device's captive portal windows are recorded under the Device of its
// map, only once captive.audit1 is negotiated; a report naming an invalid
// window is refused, and reports closer together than the interval are
// dropped.
func TestCaptiveWindowsAreRecordedForTheMapsDevice(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	recorder := &fakeCaptiveRecorder{}
	f.talk.application.options.CaptiveWindows = recorder
	closed := f.now().Add(-time.Minute)
	window := func(id string, end mtcpv1.CaptiveWindow_End) *mtcpv1.CaptiveWindow {
		return &mtcpv1.CaptiveWindow{WindowId: id, OpenedMs: closed.Add(-2 * time.Minute).UnixMilli(),
			ClosedMs: closed.UnixMilli(), End: end}
	}
	first := strings.Repeat("ab", 16)
	report := &mtcpv1.CaptiveWindowReport{Windows: []*mtcpv1.CaptiveWindow{window(first, mtcpv1.CaptiveWindow_TUNNEL_BACK)}}
	var violation protocolError
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageCaptiveWindowReport, report); !errors.As(err, &violation) {
		t.Fatalf("a report without captive.audit1: %v", err)
	}
	f.session.capabilities = append(f.session.capabilities, "captive.audit1")
	for name, bad := range map[string]*mtcpv1.CaptiveWindowReport{
		"no windows": {},
		"short id":   {Windows: []*mtcpv1.CaptiveWindow{window("ab", mtcpv1.CaptiveWindow_EXPIRED)}},
		"no end":     {Windows: []*mtcpv1.CaptiveWindow{window(first, mtcpv1.CaptiveWindow_END_UNSPECIFIED)}},
		"upper case": {Windows: []*mtcpv1.CaptiveWindow{window(strings.ToUpper(first), mtcpv1.CaptiveWindow_EXPIRED)}},
	} {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageCaptiveWindowReport, bad); !errors.As(err, &violation) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Times Core cannot take are left out, not the session's fault: a
	// window too long, or closed ahead of Core's clock.
	for name, skewed := range map[string]*mtcpv1.CaptiveWindow{
		"too long": {WindowId: first, OpenedMs: closed.Add(-time.Hour).UnixMilli(), ClosedMs: closed.UnixMilli(),
			End: mtcpv1.CaptiveWindow_EXPIRED},
		"ahead": {WindowId: first, OpenedMs: f.now().Add(time.Hour).UnixMilli(),
			ClosedMs: f.now().Add(time.Hour + time.Minute).UnixMilli(), End: mtcpv1.CaptiveWindow_EXPIRED},
	} {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageCaptiveWindowReport,
			&mtcpv1.CaptiveWindowReport{Windows: []*mtcpv1.CaptiveWindow{skewed}}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Before a map there is no Device to record it under.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageCaptiveWindowReport, report); err != nil ||
		len(recorder.windows) != 0 {
		t.Fatalf("report before a map: %v", err)
	}
	snapshot := streamFixture(t, 2)
	if err := f.talk.sink.SendSnapshot(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	// A window listed twice counts once, the first.
	twice := &mtcpv1.CaptiveWindowReport{Windows: []*mtcpv1.CaptiveWindow{
		window(first, mtcpv1.CaptiveWindow_TUNNEL_BACK), window(first, mtcpv1.CaptiveWindow_EXPIRED),
	}}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageCaptiveWindowReport, twice); err != nil {
		t.Fatal(err)
	}
	if len(recorder.windows) != 1 || recorder.devices[0] != snapshot.NodeID() || recorder.windows[0].ID != first ||
		recorder.windows[0].End != captivewindow.EndTunnelBack || recorder.windows[0].ClosedAt.Sub(recorder.windows[0].OpenedAt) != 2*time.Minute {
		t.Fatalf("recorded %+v for %v", recorder.windows, recorder.devices)
	}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageCaptiveWindowReport, report); err != nil ||
		len(recorder.windows) != 1 {
		t.Fatalf("a fast report: %v, %d recorded", err, len(recorder.windows))
	}
	f.advance(captiveReportInterval)
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageCaptiveWindowReport, report); err != nil ||
		len(recorder.windows) != 2 {
		t.Fatalf("after the interval: %v, %d recorded", err, len(recorder.windows))
	}
}

package mtcp

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
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

// TD-SEC-81: windows whose times Core cannot take cost no log line in a
// session without a map, and one line per session with a map, however many
// reports carry them; every such window of a mapped session is counted.
func TestUntakenCaptiveWindowsAreLoggedOncePerSession(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	var logs syncBuffer
	f.talk.application.options.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	f.talk.application.options.Metrics = NewMetrics()
	f.talk.application.options.CaptiveWindows = &fakeCaptiveRecorder{}
	f.session.capabilities = append(f.session.capabilities, "captive.audit1")
	ahead := make([]*mtcpv1.CaptiveWindow, 0, captivewindow.MaximumPerReport)
	for i := range captivewindow.MaximumPerReport {
		ahead = append(ahead, &mtcpv1.CaptiveWindow{WindowId: strings.Repeat(string(rune('a'+i%6)), 31) + "0",
			OpenedMs: f.now().Add(time.Hour).UnixMilli(), ClosedMs: f.now().Add(time.Hour + time.Minute).UnixMilli(),
			End: mtcpv1.CaptiveWindow_EXPIRED})
	}
	report := &mtcpv1.CaptiveWindowReport{Windows: ahead}
	for range 5 {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageCaptiveWindowReport, report); err != nil {
			t.Fatal(err)
		}
	}
	if n := logs.count("captive window times not taken"); n != 0 ||
		counterValue(t, f.talk.application.options.Metrics.captiveUntaken) != 0 {
		t.Fatalf("a session without a map logged %d lines", n)
	}
	if err := f.talk.sink.SendSnapshot(t.Context(), streamFixture(t, 2)); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageCaptiveWindowReport, report); err != nil {
			t.Fatal(err)
		}
	}
	// Windows that repeat an ID count once per report: six distinct IDs.
	if n := logs.count("captive window times not taken"); n != 1 ||
		counterValue(t, f.talk.application.options.Metrics.captiveUntaken) != 5*6 {
		t.Fatalf("a mapped session logged %d lines, counted %v", n,
			counterValue(t, f.talk.application.options.Metrics.captiveUntaken))
	}
}

func counterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(counter)
	families, err := registry.Gather()
	if err != nil || len(families) != 1 || len(families[0].GetMetric()) != 1 {
		t.Fatalf("gather: %v %v", families, err)
	}
	return families[0].GetMetric()[0].GetCounter().GetValue()
}

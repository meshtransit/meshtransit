package mtcp

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// groupRecorder keeps the reports the writer hands it.
type groupRecorder struct {
	mu      sync.Mutex
	reports []kubecluster.GatewayGroupReport
	busy    int // the first busy calls answer not kept
	failed  error
	written chan struct{}
}

func (recorder *groupRecorder) RecordGatewayGroups(_ context.Context, _ [32]byte, nodeKey []byte,
	report kubecluster.GatewayGroupReport) (bool, error) {
	recorder.mu.Lock()
	defer func() {
		recorder.mu.Unlock()
		select {
		case recorder.written <- struct{}{}:
		default:
		}
	}()
	if len(nodeKey) != 32 {
		return false, errors.New("no node key")
	}
	if recorder.busy > 0 {
		recorder.busy--
		return false, nil
	}
	if recorder.failed != nil {
		return false, recorder.failed
	}
	recorder.reports = append(recorder.reports, report)
	return true, nil
}

func (recorder *groupRecorder) kept() []kubecluster.GatewayGroupReport {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]kubecluster.GatewayGroupReport(nil), recorder.reports...)
}

// waitFor waits until the recorder kept count reports.
func (recorder *groupRecorder) waitFor(t *testing.T, count int) []kubecluster.GatewayGroupReport {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if kept := recorder.kept(); len(kept) >= count {
			return kept
		}
		select {
		case <-recorder.written:
		case <-deadline:
			t.Fatalf("kept %d reports, want %d", len(recorder.kept()), count)
		}
	}
}

func newGroupFixture(t *testing.T) (tokenFixture, *groupRecorder) {
	t.Helper()
	recorder := &groupRecorder{written: make(chan struct{}, 16)}
	clock := &testClock{current: time.Now()}
	guard := &tokenGuard{}
	trust := &tokenTrust{trust: testRotationTrust()}
	f := newFixture(t, func(options *Options) {
		options.Now = clock.now
		options.Capabilities = append(options.Capabilities, CapabilityGatewayToken, CapabilityGatewayGroups)
		options.GatewayTokens = &GatewayTokens{Guard: guard, Trust: trust, Mode: kubecluster.GatewayTokenObserve}
		options.GatewayGroups = recorder
	})
	return tokenFixture{fixture: f, guard: guard, trust: trust, clock: clock, gateway: newProvingNode(t, 0x63)},
		recorder
}

// openGateway dials a gateway session that lists capabilities.
func (f tokenFixture) openGateway(t *testing.T, capabilities ...string) *client {
	t.Helper()
	c, _, _ := f.dial(dialOptions{machine: f.gateway.machine, nodeKey: f.gateway.node.Public(),
		capabilities: capabilities})
	proof, err := sharedmtcp.NodeKeySessionProof(f.gateway.node, f.control.Public(), c.session.HandshakeHash())
	if err != nil {
		t.Fatal(err)
	}
	c.send(sharedmtcp.MessageNodeKeyProof, &mtcpv1.NodeKeyProof{Proof: proof[:]})
	return c
}

func sampleGroupReport() *mtcpv1.GatewayGroupReport {
	return &mtcpv1.GatewayGroupReport{CheckedAtMs: 1_793_000_000_000, Groups: []*mtcpv1.GatewayGroupStatus{
		{Group: "view", State: mtcpv1.GatewayGroupStatus_ENABLED, Reason: mtcpv1.GatewayGroupStatus_NONE},
		{Group: "edit", State: mtcpv1.GatewayGroupStatus_DISABLED, Reason: mtcpv1.GatewayGroupStatus_RBAC_EXCEEDS},
	}}
}

func TestGatewayGroupReportIsKept(t *testing.T) {
	f, recorder := newGroupFixture(t)
	c := f.openGateway(t, CapabilityGatewayGroups)
	c.ping()
	c.send(sharedmtcp.MessageGatewayGroupReport, sampleGroupReport())
	c.ping()
	kept := recorder.waitFor(t, 1)[0]
	want := []kubecluster.GatewayGroupStatus{
		{Group: "view", State: kubecluster.GroupStateEnabled, Reason: kubecluster.GroupReasonNone},
		{Group: "edit", State: kubecluster.GroupStateDisabled, Reason: kubecluster.GroupReasonRBACExceeds},
	}
	if !kept.Supported || len(kept.Groups) != 2 || kept.Groups[0] != want[0] || kept.Groups[1] != want[1] ||
		!kept.CheckedAt.Equal(time.UnixMilli(1_793_000_000_000)) {
		t.Fatalf("kept %+v", kept)
	}
	// A second report within 30 s waits for the next slot; a newer one
	// replaces it there.
	c.send(sharedmtcp.MessageGatewayGroupReport, sampleGroupReport())
	c.ping()
	f.clock.advance(2 * gatewayGroupReportEvery)
	c.send(sharedmtcp.MessageGatewayGroupReport, &mtcpv1.GatewayGroupReport{Truncated: true})
	c.ping()
	if kept := recorder.waitFor(t, 2); len(kept) != 2 || !kept[1].Truncated {
		t.Fatalf("kept %+v", kept)
	}
}

func TestGatewayGroupReportBreakingTheRulesEndsTheSession(t *testing.T) {
	f, recorder := newGroupFixture(t)
	c := f.openGateway(t, CapabilityGatewayGroups)
	c.ping()
	c.send(sharedmtcp.MessageGatewayGroupReport, &mtcpv1.GatewayGroupReport{Groups: []*mtcpv1.GatewayGroupStatus{
		{Group: "Edit", State: mtcpv1.GatewayGroupStatus_ENABLED, Reason: mtcpv1.GatewayGroupStatus_NONE}}})
	c.expectClosedWith(mtcpv1.Error_INVALID, "invalid group report")
	if kept := recorder.kept(); len(kept) != 0 {
		t.Fatalf("kept %+v", kept)
	}
}

func TestGatewayGroupReportWithoutTheCapability(t *testing.T) {
	f, recorder := newGroupFixture(t)
	c := f.openGateway(t)
	c.ping()
	// The gateway's meshgw cannot report: recorded as such.
	if kept := recorder.waitFor(t, 1); kept[0].Supported || len(kept[0].Groups) != 0 {
		t.Fatalf("kept %+v", kept)
	}
	c.send(sharedmtcp.MessageGatewayGroupReport, sampleGroupReport())
	errorMessage, _ := c.expect(sharedmtcp.MessageError).(*mtcpv1.Error)
	if errorMessage.GetCode() != mtcpv1.Error_UNSUPPORTED || errorMessage.GetFatal() {
		t.Fatalf("error %v", errorMessage)
	}
	c.ping()
}

func TestGatewayGroupWriterRetriesAndKeepsTheNewest(t *testing.T) {
	clock := &testClock{current: time.Now()}
	recorder := &groupRecorder{busy: 1, written: make(chan struct{}, 16)}
	writer := newGatewayGroupWriter(recorder, NewMetrics(), slog.New(slog.DiscardHandler), clock.now)
	defer writer.stop()
	nodeKey := newProvingNode(t, 0x64).node.Public()
	machine := [32]byte{1}
	writer.submit(machine, node.Key(nodeKey), kubecluster.GatewayGroupReport{Supported: true,
		ReceivedAt: clock.now()}, time.Time{})
	<-recorder.written // busy: waits 30 s
	writer.submit(machine, node.Key(nodeKey), kubecluster.GatewayGroupReport{Supported: true, Truncated: true,
		ReceivedAt: clock.now()}, time.Time{})
	if kept := recorder.waitFor(t, 1); len(kept) != 1 || !kept[0].Truncated {
		t.Fatalf("kept %+v, want the newest", kept)
	}
	writer.stop()
	writer.submit(machine, node.Key(nodeKey), kubecluster.GatewayGroupReport{Supported: true,
		ReceivedAt: clock.now()}, time.Time{})
	if kept := recorder.kept(); len(kept) != 1 {
		t.Fatalf("a stopped writer kept %+v", kept)
	}
}

func TestGatewayGroupWriterDropsFailedAndOldReports(t *testing.T) {
	clock := &testClock{current: time.Now()}
	recorder := &groupRecorder{failed: errors.New("invalid"), written: make(chan struct{}, 16)}
	writer := newGatewayGroupWriter(recorder, NewMetrics(), slog.New(slog.DiscardHandler), clock.now)
	defer writer.stop()
	nodeKey := node.Key(newProvingNode(t, 0x65).node.Public())
	writer.submit([32]byte{2}, nodeKey, kubecluster.GatewayGroupReport{Supported: true, ReceivedAt: clock.now()},
		time.Time{})
	<-recorder.written
	// A report that failed is not kept for another try.
	deadline := time.Now().Add(5 * time.Second)
	for {
		writer.mu.Lock()
		waiting := len(writer.pending)
		writer.mu.Unlock()
		if waiting == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d reports still wait after a failure", waiting)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// One older than 5 minutes is dropped unwritten.
	writer.mu.Lock()
	writer.pending[[32]byte{3}] = gatewayGroupPending{report: kubecluster.GatewayGroupReport{Supported: true,
		ReceivedAt: clock.now().Add(-gatewayGroupMaximumAge - time.Second)}}
	writer.mu.Unlock()
	if writer.writeOne() {
		t.Fatal("an old report was written")
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if len(writer.pending) != 0 {
		t.Fatal("an old report still waits")
	}
}

package mtcp

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/kubeprofile"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// ceilingRecorder keeps the ceilings the writer hands it.
type ceilingRecorder struct {
	mu       sync.Mutex
	ceilings []kubecluster.EncodedCeiling
	failed   error
	written  chan struct{}
}

func (recorder *ceilingRecorder) RecordGatewayCeiling(_ context.Context, _ [32]byte, nodeKey []byte,
	ceiling kubecluster.EncodedCeiling,
) (GatewayCeilingWrite, error) {
	recorder.mu.Lock()
	defer func() {
		recorder.mu.Unlock()
		select {
		case recorder.written <- struct{}{}:
		default:
		}
	}()
	if len(nodeKey) != 32 {
		return 0, errors.New("no node key")
	}
	if recorder.failed != nil {
		return 0, recorder.failed
	}
	recorder.ceilings = append(recorder.ceilings, ceiling)
	return GatewayCeilingWritten, nil
}

func (recorder *ceilingRecorder) kept() []kubecluster.EncodedCeiling {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]kubecluster.EncodedCeiling(nil), recorder.ceilings...)
}

// body decodes a kept ceiling's body.
func body(t *testing.T, ceiling kubecluster.EncodedCeiling) kubecluster.CeilingBody {
	t.Helper()
	var decoded kubecluster.CeilingBody
	if err := json.Unmarshal(ceiling.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func (recorder *ceilingRecorder) waitFor(t *testing.T, count int) []kubecluster.EncodedCeiling {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if kept := recorder.kept(); len(kept) >= count {
			return kept
		}
		select {
		case <-recorder.written:
		case <-deadline:
			t.Fatalf("kept %d ceilings, want %d", len(recorder.kept()), count)
		}
	}
}

func newCeilingFixture(t *testing.T) (tokenFixture, *ceilingRecorder) {
	t.Helper()
	recorder := &ceilingRecorder{written: make(chan struct{}, 16)}
	clock := &testClock{current: time.Now()}
	guard := &tokenGuard{}
	trust := &tokenTrust{trust: testRotationTrust()}
	f := newFixture(t, func(options *Options) {
		options.Now = clock.now
		options.Capabilities = append(options.Capabilities, CapabilityGatewayToken, CapabilityGatewayCeiling)
		options.GatewayTokens = &GatewayTokens{Guard: guard, Trust: trust, Mode: kubecluster.GatewayTokenObserve}
		options.GatewayCeilings = recorder
	})
	return tokenFixture{fixture: f, guard: guard, trust: trust, clock: clock, gateway: newProvingNode(t, 0x66)},
		recorder
}

func sampleCeiling(verb string) *mtcpv1.GatewayGroupCeiling {
	return &mtcpv1.GatewayGroupCeiling{CheckedAtMs: time.Now().UnixMilli(), Groups: []*mtcpv1.GatewayCeilingGroup{{
		Group: "edit", ClusterRole: "edit",
		Everywhere: &mtcpv1.GatewayCeilingScope{Measured: true, Incomplete: true},
		Namespaces: []*mtcpv1.GatewayCeilingScope{{Namespace: "default", Measured: true, RulesDropped: 2,
			Rules: []*mtcpv1.KubernetesProfileRule{
				{Verbs: []string{verb}, ApiGroups: []string{""}, Resources: []string{"pods"}},
				{Verbs: []string{"get"}, NonResourceUrls: []string{"/healthz"}},
			}}, {Namespace: "team-a"}},
	}}}
}

func TestGatewayCeilingIsKept(t *testing.T) {
	f, recorder := newCeilingFixture(t)
	c := f.openGateway(t, CapabilityGatewayCeiling)
	c.ping()
	c.send(sharedmtcp.MessageGatewayGroupCeiling, sampleCeiling("get"))
	c.ping()
	kept := recorder.waitFor(t, 1)[0]
	decoded := body(t, kept)
	edit := decoded.Groups[0]
	if len(decoded.Groups) != 1 || edit.ClusterRole != "edit" || !edit.Everywhere.Incomplete ||
		edit.Everywhere.Rules == nil || len(edit.Namespaces) != 2 || edit.Namespaces[0].RulesDropped != 2 ||
		edit.Namespaces[0].Rules[1].NonResourceURLs[0] != "/healthz" || edit.Namespaces[1].Measured ||
		edit.Namespaces[1].Rules == nil || kept.CheckedAt().IsZero() {
		t.Fatalf("kept %+v", decoded)
	}
	if _, hash, err := decoded.Encode(); err != nil || hash != kept.Hash() {
		t.Fatalf("the kept body does not encode to its hash: %v", err)
	}
	// One sent within a minute waits for the Device's minute; a newer one
	// replaces it there.
	c.send(sharedmtcp.MessageGatewayGroupCeiling, sampleCeiling("list"))
	c.send(sharedmtcp.MessageGatewayGroupCeiling, sampleCeiling("watch"))
	c.ping()
	if kept := recorder.kept(); len(kept) != 1 {
		t.Fatalf("written within the minute: %d", len(kept))
	}
	// Past the minute, the next one is written at once.
	f.clock.advance(2 * gatewayCeilingEvery)
	c.send(sharedmtcp.MessageGatewayGroupCeiling, sampleCeiling("watch"))
	c.ping()
	if kept := recorder.waitFor(t, 2); len(kept) != 2 ||
		body(t, kept[1]).Groups[0].Namespaces[0].Rules[0].Verbs[0] != "watch" {
		t.Fatalf("kept %d, want the newest second", len(kept))
	}
}

func TestGatewayCeilingBreakingTheRulesEndsTheSession(t *testing.T) {
	f, recorder := newCeilingFixture(t)
	c := f.openGateway(t, CapabilityGatewayCeiling)
	c.ping()
	invalid := sampleCeiling("get")
	invalid.Groups[0].Everywhere = nil
	c.send(sharedmtcp.MessageGatewayGroupCeiling, invalid)
	c.expectClosedWith(mtcpv1.Error_INVALID, "invalid group ceiling")
	if kept := recorder.kept(); len(kept) != 0 {
		t.Fatalf("kept %+v", kept)
	}
}

func TestGatewayCeilingWithoutTheCapability(t *testing.T) {
	f, recorder := newCeilingFixture(t)
	c := f.openGateway(t)
	c.ping()
	c.send(sharedmtcp.MessageGatewayGroupCeiling, sampleCeiling("get"))
	errorMessage, _ := c.expect(sharedmtcp.MessageError).(*mtcpv1.Error)
	if errorMessage.GetCode() != mtcpv1.Error_UNSUPPORTED || errorMessage.GetFatal() {
		t.Fatalf("error %v", errorMessage)
	}
	c.ping()
	if kept := recorder.kept(); len(kept) != 0 {
		t.Fatalf("kept %+v", kept)
	}
}

func encodedCeiling(t *testing.T, at time.Time, resource string) kubecluster.EncodedCeiling {
	t.Helper()
	ceiling, err := kubecluster.CeilingBody{Groups: []kubecluster.CeilingGroup{{
		Group: "edit", Everywhere: kubecluster.CeilingScope{Measured: true, Rules: []kubeprofile.Rule{
			{APIGroups: []string{""}, Resources: []string{resource}, Verbs: []string{"get"}},
		}},
		Namespaces: []kubecluster.CeilingScope{},
	}}}.Encoded(time.Time{}, at)
	if err != nil {
		t.Fatal(err)
	}
	return ceiling
}

// The writer keeps its byte count exact as ceilings replace each other,
// drops what does not fit its budget, what waited too long and what
// failed, and takes nothing once stopped.
func TestGatewayCeilingWriterBounds(t *testing.T) {
	clock := &testClock{current: time.Now()}
	recorder := &ceilingRecorder{failed: errors.New("invalid"), written: make(chan struct{}, 16)}
	writer := newGatewayCeilingWriter(recorder, NewMetrics(), slog.New(slog.DiscardHandler), clock.now)
	defer writer.stop()
	nodeKey := node.Key(newProvingNode(t, 0x67).node.Public())
	small, large := encodedCeiling(t, clock.now(), "pods"), encodedCeiling(t, clock.now(), strings.Repeat("r", 200))
	// Waiting for the minute after a write, so nothing is written meanwhile.
	writer.mu.Lock()
	writer.written[[32]byte{1}] = clock.now()
	writer.mu.Unlock()
	writer.submit([32]byte{1}, nodeKey, small)
	writer.submit([32]byte{1}, nodeKey, large)
	writer.mu.Lock()
	if writer.bytes != len(large.Bytes()) || len(writer.pending) != 1 {
		writer.mu.Unlock()
		t.Fatalf("bytes %d after a replacement, want %d", writer.bytes, len(large.Bytes()))
	}
	// A replacement that would pass the budget is dropped; the waiting one stays.
	writer.bytes = gatewayCeilingBudget - 1
	writer.mu.Unlock()
	writer.submit([32]byte{2}, nodeKey, small)
	writer.mu.Lock()
	if _, waits := writer.pending[[32]byte{2}]; waits {
		writer.mu.Unlock()
		t.Fatal("a ceiling over the budget waits")
	}
	writer.bytes = len(large.Bytes())
	delete(writer.written, [32]byte{1})
	writer.mu.Unlock()
	// Due now: written, failed, dropped; the count comes back to zero.
	writer.submit([32]byte{1}, nodeKey, small)
	<-recorder.written
	deadline := time.Now().Add(5 * time.Second)
	for {
		writer.mu.Lock()
		waiting, bytes := len(writer.pending), writer.bytes
		writer.mu.Unlock()
		if waiting == 0 && bytes == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d ceilings, %d bytes still wait after a failure", waiting, bytes)
		}
		time.Sleep(10 * time.Millisecond)
	}
	old := encodedCeiling(t, clock.now().Add(-gatewayCeilingMaximumAge-time.Second), "pods")
	writer.mu.Lock()
	writer.pending[[32]byte{3}] = gatewayCeilingPending{ceiling: old}
	writer.bytes += len(old.Bytes())
	writer.mu.Unlock()
	if writer.writeOne() {
		t.Fatal("an old ceiling was written")
	}
	writer.mu.Lock()
	if len(writer.pending) != 0 || writer.bytes != 0 {
		writer.mu.Unlock()
		t.Fatal("an old ceiling still waits")
	}
	writer.mu.Unlock()
	writer.stop()
	writer.submit([32]byte{4}, nodeKey, small)
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if len(writer.pending) != 0 {
		t.Fatal("a stopped writer took a ceiling")
	}
}

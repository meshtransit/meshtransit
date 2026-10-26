package mtcp

import (
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// Each gate refusal of a gateway's keys is reported with its reason; a
// wrong proof, which anyone with the machine key could send, is not.
func TestGatewayGateRefusalsAreReported(t *testing.T) {
	for _, test := range []struct {
		name   string
		check  TimestampCheck
		commit bool
		wrong  bool
		reason kubecluster.KeyEventReason
	}{
		{name: "retired machine key", check: TimestampCheck{Accepted: true, Gateway: true, Machine: MachineRetired},
			commit: true, reason: kubecluster.KeyEventRetiredMachineKey},
		{name: "node key not current", check: TimestampCheck{Accepted: true, Gateway: true, Machine: MachineCurrent},
			commit: true, reason: kubecluster.KeyEventStaleNodeKey},
		// A failed commit may be keys that stopped being current: not audited.
		{name: "commit refused", check: currentGateway},
		{name: "replayed before the proof", check: TimestampCheck{Gateway: true, Machine: MachineCurrent,
			NodeCurrent: true}, commit: true, reason: kubecluster.KeyEventReplayedHandshake},
		{name: "wrong proof", check: currentGateway, commit: true, wrong: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			gateway := newProvingNode(t, 0x45)
			recorder := &keyRecorderStub{outcome: kubecluster.KeyEventRecorded}
			guard := &gatewayGuard{checks: map[[32]byte]TimestampCheck{gateway.fingerprint(): test.check},
				commitOK: test.commit}
			f := newFixture(t, func(options *Options) { options.Guard, options.GatewayKeys = guard, recorder })
			c, _, _ := f.dial(dialOptions{machine: gateway.machine, nodeKey: gateway.node.Public()})
			proving := gateway.node
			if test.wrong {
				proving = newProvingNode(t, 0x55).node
			}
			c.proveNodeKey(proving, f.control.Public())
			failure := c.expect(sharedmtcp.MessageError).(*mtcpv1.Error)
			if failure.GetCode() != mtcpv1.Error_NOT_AUTHORIZED {
				t.Fatalf("refusal %+v", failure)
			}
			if test.reason == "" {
				time.Sleep(20 * time.Millisecond)
				if got := recorder.reports(); len(got) != 0 {
					t.Fatalf("a wrong proof was reported: %+v", got)
				}
				return
			}
			got := waitReports(t, recorder, 1)
			if got[0].machine != gateway.fingerprint() || got[0].reason != test.reason || got[0].suppressed != 0 {
				t.Fatalf("report %+v", got[0])
			}
		})
	}
}

// Only the replacement of a live, receiving map stream counts toward a
// fight, and only twice within the window is one: a pod's start replaces
// sessions that never streamed, and a broken path leaves one that receives
// nothing.
func TestGatewayFightNeedsALiveStreamTwice(t *testing.T) {
	clock := &testClock{}
	clock.set(time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC))
	f := newFixture(t, func(options *Options) { options.Now = clock.now })
	machine := newProvingNode(t, 0x65).machine.Public()
	session := func(streaming bool, received time.Duration) *Session {
		previous := &Session{}
		previous.streaming.Store(streaming)
		previous.lastReceive.Store(clock.now().Add(-received).UnixNano())
		return previous
	}
	fight := func(previous *Session) bool {
		f.server.mu.Lock()
		defer f.server.mu.Unlock()
		return f.server.fightLocked(machine, previous)
	}
	// A pod's start: the probe and the rotation never streamed.
	for range 3 {
		if fight(session(false, 0)) {
			t.Fatal("a pod's start is a fight")
		}
	}
	// A half-open stream: nothing received since the path broke.
	for range 3 {
		if fight(session(true, time.Minute)) {
			t.Fatal("a half-open stream is a fight")
		}
	}
	if fight(session(true, time.Second)) {
		t.Fatal("one replaced stream is a fight")
	}
	if !fight(session(true, time.Second)) {
		t.Fatal("two replaced live streams are no fight")
	}
	// The window starts again after five minutes.
	clock.advance(gatewayFightWindow)
	if fight(session(true, time.Second)) {
		t.Fatal("a replacement after the window is a fight")
	}
}

// The fight memory stays bounded.
func TestGatewayFightsAreBounded(t *testing.T) {
	clock := &testClock{}
	clock.set(time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC))
	f := newFixture(t, func(options *Options) { options.Now = clock.now })
	live := &Session{}
	live.streaming.Store(true)
	live.lastReceive.Store(clock.now().UnixNano())
	f.server.mu.Lock()
	defer f.server.mu.Unlock()
	for index := range maxContestedGateways + 10 {
		var raw [32]byte
		raw[0], raw[1], raw[2] = byte(index), byte(index>>8), 1
		machine, err := key.MachinePrivateFromBytes(raw[:])
		if err != nil {
			t.Fatal(err)
		}
		f.server.fightLocked(machine.Public(), live)
	}
	if len(f.server.fights) > maxContestedGateways {
		t.Fatalf("%d fights remembered", len(f.server.fights))
	}
}

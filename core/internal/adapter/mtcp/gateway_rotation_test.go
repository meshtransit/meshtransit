package mtcp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// fakeGatewayPresence answers rotation checks for a gateway's presence.
type fakeGatewayPresence struct {
	mu       sync.Mutex
	state    mapsession.GatewayRotationState
	err      error
	block    chan struct{}
	checks   []node.PresenceLease
	released []node.PresenceLease
}

func (presence *fakeGatewayPresence) AcquireGatewayPresence(context.Context, network.Scope, node.PresenceLease,
	time.Duration) (mapsession.GatewayClaim, error) {
	return mapsession.GatewayClaim{Claimed: true}, nil
}

func (presence *fakeGatewayPresence) RenewGatewayPresence(context.Context, node.PresenceLease) (bool, error) {
	return true, nil
}

func (presence *fakeGatewayPresence) ReleaseGatewayPresence(ctx context.Context, _ network.Scope,
	lease node.PresenceLease) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	presence.mu.Lock()
	defer presence.mu.Unlock()
	presence.released = append(presence.released, lease)
	return true, nil
}

func (presence *fakeGatewayPresence) releases() []node.PresenceLease {
	presence.mu.Lock()
	defer presence.mu.Unlock()
	return append([]node.PresenceLease(nil), presence.released...)
}

func (presence *fakeGatewayPresence) HandOffGatewayPresence(context.Context, node.PresenceLease) (bool, error) {
	return true, nil
}

func (presence *fakeGatewayPresence) CheckGatewayRotation(ctx context.Context,
	lease node.PresenceLease) (mapsession.GatewayRotationState, error) {
	presence.mu.Lock()
	presence.checks = append(presence.checks, lease)
	block, state, err := presence.block, presence.state, presence.err
	presence.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return state, err
}

func (presence *fakeGatewayPresence) checked() []node.PresenceLease {
	presence.mu.Lock()
	defer presence.mu.Unlock()
	return append([]node.PresenceLease(nil), presence.checks...)
}

// rotateNodeKey sends a gateway's RotateNodeKey.
func (f *conversationFixture) rotateNodeKey() error {
	f.t.Helper()
	_, newKey, nodeProof, discoKey, discoProof := f.keys(6)
	return f.talk.Receive(f.t.Context(), sharedmtcp.MessageRotateNodeKey, &mtcpv1.RotateNodeKey{
		NewNodeKey: newKey, NodeKeyProof: nodeProof, NewDiscoKey: discoKey, DiscoKeyProof: discoProof})
}

// expectRotationRefused expects a rotation refused for good, the session
// kept: the node drops its staged key and goes on (K1a1 plan §16.12).
func (f *conversationFixture) expectRotationRefused(kind sharedmtcp.MessageType, rotations *fakeMachineKeyRotations) {
	f.t.Helper()
	got := f.expectPast(sharedmtcp.MessageError).(*mtcpv1.Error)
	if got.GetCode() != mtcpv1.Error_NOT_PERMITTED || got.GetFatal() || got.GetRetryAfterMs() != 0 {
		f.t.Fatalf("%#x answered %v", uint8(kind), got)
	}
	if len(rotations.calls()) != 0 || len(f.registrations.calls()) != 0 {
		f.t.Fatalf("%#x reached a store", uint8(kind))
	}
}

func rotationKinds() []sharedmtcp.MessageType {
	return []sharedmtcp.MessageType{sharedmtcp.MessageRotateMachineKey, sharedmtcp.MessageRotateNodeKey}
}

func (f *conversationFixture) rotate(kind sharedmtcp.MessageType) error {
	if kind == sharedmtcp.MessageRotateMachineKey {
		_, err := f.rotateMachineKey(0x44, 0x44)
		return err
	}
	return f.rotateNodeKey()
}

// A gateway rotates only while its stream holds the presence and Redis says
// the keys are neither contested nor held by another stream.
func TestGatewayRotationNeedsItsPresence(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		state   mapsession.GatewayRotationState
		err     error
		noStore bool
		noClaim bool
	}{
		{name: "contested", state: mapsession.GatewayRotationContested},
		{name: "held by another stream", state: mapsession.GatewayRotationNotHeld},
		{name: "redis failed", err: errors.New("redis: down")},
		{name: "no store", noStore: true},
		{name: "the stream never claimed", state: mapsession.GatewayRotationHeld, noClaim: true},
	} {
		for _, kind := range rotationKinds() {
			t.Run(fmt.Sprintf("%s %#x", test.name, uint8(kind)), func(t *testing.T) {
				t.Parallel()
				rotations := &fakeMachineKeyRotations{}
				presence := &fakeGatewayPresence{state: test.state, err: test.err}
				f := gatewayFixture(t, rotations)
				if test.noStore {
					f.talk.application.options.GatewayPresence = nil
				} else {
					f.talk.application.options.GatewayPresence = presence
				}
				f.streams.skipClaim = test.noClaim
				f.run()
				f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
				if err := f.rotate(kind); err != nil {
					t.Fatalf("Receive() = %v, want the session kept", err)
				}
				f.expectRotationRefused(kind, rotations)
			})
		}
	}
}

// The check names the lease this session's stream claimed.
func TestGatewayRotationChecksTheStreamsLease(t *testing.T) {
	t.Parallel()
	for _, kind := range rotationKinds() {
		rotations := &fakeMachineKeyRotations{}
		presence := &fakeGatewayPresence{state: mapsession.GatewayRotationHeld}
		f := gatewayFixture(t, rotations)
		f.talk.application.options.GatewayPresence = presence
		f.run()
		f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
		_ = f.rotate(kind)
		checks := presence.checked()
		claimed := f.streams.claimedLeases()
		if len(checks) != 1 || len(claimed) == 0 || checks[0] != claimed[0] || !checks[0].Gateway() {
			t.Fatalf("%#x: checked %+v, claimed %+v", uint8(kind), checks, claimed)
		}
	}
}

// While its machine key is contested on this replica a gateway rotates
// neither key; the refusal is definitive and keeps the session.
func TestLocallyContestedGatewayRotatesNoKey(t *testing.T) {
	t.Parallel()
	for _, kind := range rotationKinds() {
		rotations := &fakeMachineKeyRotations{}
		f := gatewayFixture(t, rotations)
		f.session.server.mu.Lock()
		f.session.server.contested[f.session.Machine()] = time.Now().Add(time.Minute)
		f.session.server.mu.Unlock()
		f.run()
		f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
		if err := f.rotate(kind); err != nil {
			t.Fatalf("%#x: Receive() = %v", uint8(kind), err)
		}
		f.expectRotationRefused(kind, rotations)
	}
}

// A session another one replaced, or one ending, rotates nothing.
func TestReplacedGatewaySessionRotatesNoKey(t *testing.T) {
	t.Parallel()
	for _, kind := range rotationKinds() {
		rotations := &fakeMachineKeyRotations{}
		f := gatewayFixture(t, rotations)
		f.run()
		f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
		f.session.server.mu.Lock()
		delete(f.session.server.byMachine, f.session.Machine())
		f.session.server.mu.Unlock()
		if err := f.rotate(kind); err != nil {
			t.Fatalf("%#x: Receive() = %v", uint8(kind), err)
		}
		f.expectRotationRefused(kind, rotations)
	}
}

// A slow Redis bounds the check: the rotation is refused, not stalled.
func TestGatewayRotationCheckIsBounded(t *testing.T) {
	t.Parallel()
	rotations := &fakeMachineKeyRotations{}
	presence := &fakeGatewayPresence{state: mapsession.GatewayRotationHeld, block: make(chan struct{})}
	f := gatewayFixture(t, rotations)
	f.talk.application.options.GatewayPresence = presence
	f.talk.application.gatewayCheckTimeout = 20 * time.Millisecond
	f.run()
	f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
	started := time.Now()
	if _, err := f.rotateMachineKey(0x44, 0x44); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("the check took %s", elapsed)
	}
	f.expectRotationRefused(sharedmtcp.MessageRotateMachineKey, rotations)
}

// A gateway stream that lost its presence to another holder, or found one
// still ending here, tells the node SESSION_REPLACED: the gateway comes back
// at once instead of backing off (K1a1 plan §16.12).
func TestGatewayStreamLosingItsPresenceIsReplaced(t *testing.T) {
	t.Parallel()
	for _, end := range []error{mapsession.ErrPresenceTaken, mapsession.ErrPresenceConflict} {
		f := gatewayFixture(t, &fakeMachineKeyRotations{})
		f.streams.endFor = func(node.Key) error { return end }
		done := make(chan error, 1)
		go func() { done <- f.talk.Run(t.Context()) }()
		got := f.expectPast(sharedmtcp.MessageError).(*mtcpv1.Error)
		if got.GetCode() != mtcpv1.Error_SESSION_REPLACED || !got.GetFatal() {
			t.Fatalf("%v: answered %v", end, got)
		}
		if err := <-done; !errors.Is(err, end) {
			t.Fatalf("Run() = %v, want %v", err, end)
		}
	}
}

// A claim that made the keys fought over contests them here and reports a
// session fight.
func TestGatewayFightOnClaimIsReported(t *testing.T) {
	t.Parallel()
	f := gatewayFixture(t, &fakeMachineKeyRotations{})
	recorder := &keyRecorderStub{outcome: kubecluster.KeyEventRecorded}
	server := f.session.server
	server.keyReports = newGatewayKeyReporter(recorder, server.options.Metrics, server.options.Logger, time.Now, 8)
	t.Cleanup(server.keyReports.stop)
	f.streams.fight = true
	f.run()
	f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
	got := waitReports(t, recorder, 1)
	if got[0].reason != kubecluster.KeyEventSessionFight ||
		got[0].machine != node.MachineKey(f.session.Machine()).Fingerprint() {
		t.Fatalf("report %+v", got[0])
	}
	if server.rotationWait(f.session.Machine()) <= 0 {
		t.Fatal("the fought keys are not contested here")
	}
}

// Core moving the session (Shed, Shutdown) hands the presence off; any
// other end releases it.
func TestGatewaySinkHandsOffOnlyWhenCoreMovesTheSession(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		cause error
		want  bool
	}{
		{cause: errShed, want: true},
		{cause: errShuttingDown, want: true},
		{cause: ErrSessionReplaced},
		{cause: context.Canceled},
		{cause: errSendDeadline},
	} {
		f := gatewayFixture(t, &fakeMachineKeyRotations{})
		sink := &gatewayStreamSink{mapSink: f.talk.sink, conversation: f.talk}
		f.session.close(test.cause)
		if got := sink.HandsOffPresence(); got != test.want {
			t.Errorf("%v: hands off %t", test.cause, got)
		}
	}
}

// A machine key rotation keeps the stream's presence while it commits, so
// a copy's stream claiming meanwhile is a take; then it releases the lease
// by holder, before the stream resumes after a refusal (K1a1 plan §16.12).
func TestGatewayMachineRotationKeepsThenReleasesItsPresence(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	for _, commitErr := range []error{nil, kubecluster.ErrMachineKeyUsed} {
		rotations := &fakeMachineKeyRotations{err: commitErr}
		presence := &fakeGatewayPresence{state: mapsession.GatewayRotationHeld}
		f := gatewayFixture(t, rotations)
		f.talk.application.options.GatewayPresence = presence
		helloKey := node.Key(f.session.Hello().GetNodeKey())
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- f.talk.Run(ctx) }()
		f.expectStream(helloKey)
		sink := &gatewayStreamSink{mapSink: f.talk.sink, conversation: f.talk}
		rotations.during = func() {
			if !sink.KeepsPresence() {
				t.Error("the presence was not kept while the rotation committed")
			}
			if len(presence.releases()) != 0 {
				t.Error("the presence was released before the rotation was decided")
			}
		}
		_, err := f.rotateMachineKey(0x44, 0x44)
		claimed := f.streams.claimedLeases()
		if released := presence.releases(); len(released) != 1 || released[0] != claimed[0] {
			t.Fatalf("%v: released %+v, claimed %+v", commitErr, released, claimed)
		}
		if sink.KeepsPresence() {
			t.Fatalf("%v: the presence is still kept", commitErr)
		}
		if commitErr == nil {
			if !errors.Is(err, errMachineKeyRotated) {
				t.Fatalf("Receive() = %v", err)
			}
		} else {
			f.expectStream(helloKey) // resumed after the release
		}
		cancel()
		<-done
	}
}

// The claim ends with its stream: a rotation after the stream ended, or of
// a stream that ended without claiming, is refused at once.
func TestGatewayClaimEndsWithItsStream(t *testing.T) {
	t.Parallel()
	for _, skipClaim := range []bool{false, true} {
		rotations := &fakeMachineKeyRotations{}
		f := gatewayFixture(t, rotations)
		f.talk.application.gatewayClaimWait = 5 * time.Second
		f.streams.skipClaim = skipClaim
		f.streams.endFor = func(node.Key) error { return mapsession.ErrUnauthorized }
		f.run()
		f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
		f.expectPast(sharedmtcp.MessageLifecycle)
		started := time.Now()
		if _, err := f.rotateMachineKey(0x44, 0x44); err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("skip claim %t: refused after %s", skipClaim, elapsed)
		}
		got := f.expectPast(sharedmtcp.MessageError).(*mtcpv1.Error)
		if got.GetCode() != mtcpv1.Error_NOT_PERMITTED || len(rotations.calls()) != 0 {
			t.Fatalf("skip claim %t: answered %v", skipClaim, got)
		}
	}
}

// A session replaced while it waits for its claim rotates nothing.
func TestGatewaySessionReplacedWhileWaitingRotatesNoKey(t *testing.T) {
	t.Parallel()
	rotations := &fakeMachineKeyRotations{}
	f := gatewayFixture(t, rotations)
	f.streams.skipClaim = true
	f.talk.application.gatewayClaimWait = 5 * time.Second
	f.run()
	f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
	answered := make(chan error, 1)
	go func() {
		_, err := f.rotateMachineKey(0x44, 0x44)
		answered <- err
	}()
	time.Sleep(20 * time.Millisecond)
	f.session.server.mu.Lock()
	delete(f.session.server.byMachine, f.session.Machine())
	f.session.server.mu.Unlock()
	holder, _ := node.NewPresenceHolder()
	lease := must(must(node.NewPresenceLease(f.streams.snapshot.NodeID(), f.streams.snapshot.SessionGeneration(),
		"control-test", 30*time.Second)).WithGateway(holder, node.MachineKey(f.session.Machine()).Fingerprint()))
	(&gatewayStreamSink{mapSink: f.talk.sink, conversation: f.talk, generation: f.talk.currentGeneration()}).
		PresenceClaimed(f.streams.snapshot.Scope(), lease)
	if err := <-answered; err != nil {
		t.Fatal(err)
	}
	f.expectRotationRefused(sharedmtcp.MessageRotateMachineKey, rotations)
}

// The contested keys a replica remembers stay bounded while every contest
// is live: the one ending soonest gives way to a new one.
func TestLiveContestsAreBounded(t *testing.T) {
	t.Parallel()
	f := gatewayFixture(t, &fakeMachineKeyRotations{})
	server := f.session.server
	base := time.Now()
	server.mu.Lock()
	defer server.mu.Unlock()
	var first, last key.MachinePublic
	for index := range maxContestedGateways + 5 {
		var machine key.MachinePublic
		machine[0], machine[1], machine[2] = byte(index), byte(index>>8), 0x5c
		server.options.Now = func() time.Time { return base.Add(time.Duration(index) * time.Millisecond) }
		server.contestLocked(machine)
		if index == 0 {
			first = machine
		}
		last = machine
	}
	if len(server.contested) > maxContestedGateways {
		t.Fatalf("%d contests remembered", len(server.contested))
	}
	if _, kept := server.contested[last]; !kept {
		t.Fatal("the newest contest was dropped")
	}
	if _, kept := server.contested[first]; kept {
		t.Fatal("the contest ending soonest was kept")
	}
}

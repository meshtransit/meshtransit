package mtcpclient

import (
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// gatewayClient is the fake Core's client in Kubernetes gateway mode.
func (core *fakeCore) gatewayClient() *Client {
	client := core.client()
	client.gateway = newGatewayClock()
	return client
}

// provingCore offers session.proof1 and checks that every session starts
// with a valid NodeKeyProof for its hello node key; gate, when it returns
// an Error, answers the proof with it.
func provingCore(t *testing.T, gate func() *mtcpv1.Error, then func(*coreSession)) *fakeCore {
	t.Helper()
	core := newFakeCore(t)
	core.set(func(fake *fakeCore) {
		fake.extra = []string{gatewayCapability}
		fake.serve = func(s *coreSession) {
			_, first, err := s.receive(5 * time.Second)
			if err != nil {
				return
			}
			proof, ok := first.(*mtcpv1.NodeKeyProof)
			if !ok || len(s.hello.GetNodeKey()) != key.Size || !sharedmtcp.VerifyNodeKeySessionProof(s.control, s.hash,
				[key.Size]byte(s.hello.GetNodeKey()), proof.GetProof()) {
				_ = s.send(sharedmtcp.MessageError, &mtcpv1.Error{
					Code: mtcpv1.Error_NOT_AUTHORIZED, Fatal: true,
					Message: "a Kubernetes gateway must prove its node key first",
				})
				return
			}
			if gate != nil {
				if failure := gate(); failure != nil {
					_ = s.send(sharedmtcp.MessageError, failure)
					if failure.GetFatal() {
						return
					}
				}
			}
			then(s)
		}
	})
	return core
}

func gatewayTrust(t *testing.T, core *fakeCore) controlplane.TrustResult {
	t.Helper()
	var serve func(*coreSession)
	var extra []string
	core.set(func(fake *fakeCore) { serve, fake.serve, extra, fake.extra = fake.serve, answerPings, fake.extra, nil })
	trust, err := core.client().BootstrapTrust(t.Context(), core.origin(),
		controlplane.ControlKeyFingerprint(core.controlKey().Public()))
	core.set(func(fake *fakeCore) { fake.serve, fake.extra = serve, extra })
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

func TestGatewayProbeProvesFirst(t *testing.T) {
	t.Parallel()
	core := provingCore(t, nil, answerPings)
	trust := gatewayTrust(t, core)
	if err := core.gatewayClient().ProbeGateway(t.Context(), core.origin(), trust.Material, trust.Fingerprint); err != nil {
		t.Fatalf("Probe() = %v", err)
	}
	hellos, _ := core.sessions()
	last := hellos[len(hellos)-1]
	if !slices.Contains(last.GetCapabilities(), gatewayCapability) || len(last.GetNodeKey()) != key.Size {
		t.Fatalf("hello %v", last)
	}
}

// A Core without node key proofs is not used: the gateway waits.
func TestGatewayProbeNeedsProofSupport(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	var received atomic.Int32
	core.set(func(fake *fakeCore) {
		fake.serve = func(s *coreSession) {
			if _, _, err := s.receive(time.Second); err == nil {
				received.Add(1)
			}
		}
	})
	trust := gatewayTrust(t, core)
	err := core.gatewayClient().ProbeGateway(t.Context(), core.origin(), trust.Material, trust.Fingerprint)
	if !errors.Is(err, controlplane.ErrGatewayProofUnsupported) ||
		!errors.Is(err, controlplane.ErrRegistrationTemporary) {
		t.Fatalf("Probe() = %v", err)
	}
	if received.Load() != 0 {
		t.Fatal("the gateway sent a record to a Core without proofs")
	}
}

func TestGatewayGateErrors(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		failure *mtcpv1.Error
		want    error
	}{
		{
			&mtcpv1.Error{Code: mtcpv1.Error_NOT_AUTHORIZED, Fatal: true, Message: "machine key is retired"},
			controlplane.ErrMachineKeyRetired,
		},
		{
			&mtcpv1.Error{Code: mtcpv1.Error_NOT_AUTHORIZED, Fatal: true, Message: "node key is not current"},
			controlplane.ErrNodeKeyNotCurrent,
		},
		{
			&mtcpv1.Error{Code: mtcpv1.Error_NOT_AUTHORIZED, Fatal: true, Message: "handshake replayed"},
			controlplane.ErrGatewayContested,
		},
		{
			&mtcpv1.Error{Code: mtcpv1.Error_NOT_AUTHORIZED, Fatal: true, Message: "handshake timestamp is ahead of Core"},
			controlplane.ErrGatewayClock,
		},
		{
			&mtcpv1.Error{Code: mtcpv1.Error_NOT_AUTHORIZED, Message: "machine key is not bound"},
			controlplane.ErrMachineKeyUnbound,
		},
		{
			&mtcpv1.Error{Code: mtcpv1.Error_SESSION_REPLACED, Fatal: true, Message: "a newer session"},
			controlplane.ErrGatewayContested,
		},
	} {
		core := provingCore(t, func() *mtcpv1.Error { return test.failure }, answerPings)
		trust := gatewayTrust(t, core)
		err := core.gatewayClient().ProbeGateway(t.Context(), core.origin(), trust.Material, trust.Fingerprint)
		if !errors.Is(err, test.want) {
			t.Errorf("%q: Probe() = %v, want %v", test.failure.GetMessage(), err, test.want)
		}
	}
}

// A gateway's clock follows Core's: its timestamps are near Core's time
// even when its own clock is off, and never repeat for a machine key.
func TestGatewayTimestampsFollowCore(t *testing.T) {
	t.Parallel()
	for _, skew := range []time.Duration{30 * time.Second, -3 * time.Second} {
		core := provingCore(t, nil, answerPings)
		trust := gatewayTrust(t, core)
		client := core.gatewayClient()
		client.now = func() time.Time { return time.Now().Add(skew) }
		var err error
		for range 3 {
			if err = client.ProbeGateway(t.Context(), core.origin(), trust.Material, trust.Fingerprint); err == nil ||
				!errors.Is(err, controlplane.ErrGatewayClock) {
				break
			}
		}
		if err != nil {
			t.Fatalf("skew %v: Probe() = %v", skew, err)
		}
		if err := client.ProbeGateway(t.Context(), core.origin(), trust.Material, trust.Fingerprint); err != nil {
			t.Fatalf("skew %v: second Probe() = %v", skew, err)
		}
		hellos, _ := core.sessions()
		last, previous := hellos[len(hellos)-1], hellos[len(hellos)-2]
		if ahead := time.Until(time.UnixMilli(last.GetTimestampMs())); ahead > 4*time.Second || ahead < -4*time.Second {
			t.Errorf("skew %v: hello is %v off Core's time", skew, ahead)
		}
		if last.GetTimestampMs() <= previous.GetTimestampMs() {
			t.Errorf("skew %v: timestamps did not increase", skew)
		}
	}
}

func TestRotateMachineKey(t *testing.T) {
	t.Parallel()
	next, err := key.NewMachinePrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		answer func(*coreSession)
		want   error
		retry  bool
	}{
		{name: "rotated", answer: func(s *coreSession) {
			_ = s.send(sharedmtcp.MessageRotateMachineKeyResponse, &mtcpv1.RotateMachineKeyResponse{})
		}},
		{name: "refused", answer: func(s *coreSession) {
			_ = s.send(sharedmtcp.MessageError, &mtcpv1.Error{
				Code:    mtcpv1.Error_NOT_PERMITTED,
				Message: "the new machine key was used before",
			})
		}, want: controlplane.ErrMachineKeyRotationRefused},
		{name: "contested", answer: func(s *coreSession) {
			_ = s.send(sharedmtcp.MessageError, &mtcpv1.Error{
				Code: mtcpv1.Error_OVERLOADED, Fatal: true,
				RetryAfterMs: 7000, Message: "reconnect before rotating",
			})
		}, want: controlplane.ErrRegistrationTemporary, retry: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var rotated atomic.Bool
			core := provingCore(t, nil, func(s *coreSession) {
				if _, ping, err := s.receive(5 * time.Second); err != nil {
					return
				} else if _, ok := ping.(*mtcpv1.Ping); !ok {
					return
				}
				_ = s.send(sharedmtcp.MessagePong, &mtcpv1.Pong{})
				_, message, err := s.receive(5 * time.Second)
				request, ok := message.(*mtcpv1.RotateMachineKey)
				if err != nil || !ok || len(request.GetNewMachineKey()) != key.Size ||
					!sharedmtcp.VerifyMachineKeyRotationProof(s.control, s.hash, [key.Size]byte(request.GetNewMachineKey()),
						request.GetProof()) {
					return
				}
				rotated.Store(true)
				test.answer(s)
			})
			trust := gatewayTrust(t, core)
			err := core.gatewayClient().RotateMachineKey(t.Context(), core.origin(), trust.Material, trust.Fingerprint,
				next)
			if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) || !rotated.Load() {
				t.Fatalf("RotateMachineKey() = %v (sent %t)", err, rotated.Load())
			}
			if test.retry && controlplane.RetryAfterOf(err) != 7*time.Second {
				t.Fatalf("retry after %v", controlplane.RetryAfterOf(err))
			}
		})
	}
}

// joinCore answers cluster joins: pending with an admin approval, then
// authorized after approveAfter when set.
func joinCore(t *testing.T, approveAfter time.Duration, nonce [32]byte) *fakeCore {
	t.Helper()
	core := newFakeCore(t)
	core.set(func(fake *fakeCore) {
		fake.serve = func(s *coreSession) {
			_, message, err := s.receive(5 * time.Second)
			request, ok := message.(*mtcpv1.RegisterRequest)
			if err != nil || !ok {
				return
			}
			join := request.GetAuth().GetClusterJoin()
			if join.GetJoinKey() != "mtk1.good" || string(join.GetReported()) != `{"pod":"meshgw-0"}` {
				_ = s.send(sharedmtcp.MessageRegisterResponse, &mtcpv1.RegisterResponse{
					Outcome: &mtcpv1.RegisterResponse_Rejected_{Rejected: &mtcpv1.RegisterResponse_Rejected{
						Code: mtcpv1.RegisterResponse_Rejected_CREDENTIAL_INVALID,
					}},
				})
				return
			}
			_ = s.send(sharedmtcp.MessageRegisterResponse, &mtcpv1.RegisterResponse{
				Outcome: &mtcpv1.RegisterResponse_Pending_{Pending: &mtcpv1.RegisterResponse_Pending{
					ExpiresMs: time.Now().Add(10 * time.Minute).UnixMilli(),
					AdminApproval: &mtcpv1.RegisterResponse_AdminApproval{
						ClusterId: "01890f90-0000-7000-8000-0000000000c1", RequestId: "01890f90-0000-7000-8000-0000000000d1",
						RequestNonce: nonce[:],
					},
				}},
			})
			if approveAfter <= 0 {
				_, _, _ = s.receive(3 * time.Second)
				return
			}
			time.Sleep(approveAfter)
			_ = s.send(sharedmtcp.MessageRegisterResponse, &mtcpv1.RegisterResponse{
				Outcome: &mtcpv1.RegisterResponse_Authorized_{Authorized: &mtcpv1.RegisterResponse_Authorized{}},
			})
		}
	})
	return core
}

func TestClusterJoin(t *testing.T) {
	t.Parallel()
	nonce := [32]byte{1, 2, 3}
	options := func(trust controlplane.TrustResult, wait time.Duration) controlplane.RegisterOptions {
		return controlplane.RegisterOptions{
			Hostname: "meshgw-0", Version: "meshgw/test",
			PinnedFingerprint: trust.Fingerprint, JoinWait: wait,
			ClusterJoin: &controlplane.ClusterJoin{JoinKey: "mtk1.good", Reported: map[string]string{"pod": "meshgw-0"}},
		}
	}
	// Waiting: the approval is reported with what the code binds.
	waiting := joinCore(t, 0, nonce)
	trust := gatewayTrust(t, waiting)
	result, err := waiting.gatewayClient().Register(t.Context(), waiting.origin(), trust.Material,
		options(trust, 200*time.Millisecond))
	approval := result.Approval
	if err != nil || result.State != controlplane.RegistrationStateAdminApprovalRequired || approval == nil ||
		approval.RequestID != "01890f90-0000-7000-8000-0000000000d1" || approval.RequestNonce != nonce ||
		approval.ClusterID != [16]byte{0x01, 0x89, 0x0f, 0x90, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0xc1} ||
		time.Until(approval.ExpiresAt) < 9*time.Minute {
		t.Fatalf("Register() = %+v %+v, %v", result, approval, err)
	}
	hellos, _ := waiting.sessions()
	if len(hellos) == 0 {
		t.Fatal("no session")
	}
	// Approved while the session waits: Core answers on its own.
	approved := joinCore(t, 100*time.Millisecond, nonce)
	trust = gatewayTrust(t, approved)
	result, err = approved.gatewayClient().Register(t.Context(), approved.origin(), trust.Material,
		options(trust, 5*time.Second))
	if err != nil || result.State != controlplane.RegistrationStateAuthorized {
		t.Fatalf("approved Register() = %+v, %v", result, err)
	}
	// A wrong key is refused.
	refusing := joinCore(t, 0, nonce)
	trust = gatewayTrust(t, refusing)
	bad := options(trust, time.Second)
	bad.ClusterJoin.JoinKey = "mtk1.bad"
	if _, err := refusing.gatewayClient().Register(t.Context(), refusing.origin(), trust.Material, bad); !errors.Is(err,
		controlplane.ErrRegistration) || errors.Is(err, controlplane.ErrRegistrationTemporary) ||
		!strings.Contains(err.Error(), "credential_invalid") {
		t.Fatalf("a wrong join key = %v", err)
	}
}

// An ordinary client declares no node key proof and opens with a Ping.
func TestOrdinaryClientDeclaresNoProof(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	core.set(func(fake *fakeCore) { fake.extra = []string{gatewayCapability} })
	trust := gatewayTrust(t, core)
	if err := core.client().VerifyTrust(t.Context(), core.origin(), trust.Material, trust.Fingerprint); err != nil {
		t.Fatal(err)
	}
	for _, hello := range func() []*mtcpv1.ClientHello { hellos, _ := core.sessions(); return hellos }() {
		if slices.Contains(hello.GetCapabilities(), gatewayCapability) {
			t.Fatal("an ordinary client declared session.proof1")
		}
	}
}

// A timestamp Core never recorded is taken back, so a hello sent ahead
// does not hold the next ones ahead; Core's time out of range is ignored.
func TestGatewayClock(t *testing.T) {
	t.Parallel()
	clock := newGatewayClock()
	machine := key.MachinePublic{1}
	local := time.UnixMilli(1_800_000_000_000)
	clock.observe(local.Add(-30*time.Second), local, true) // the local clock is 30 s ahead
	first, previous := clock.timestamp(machine, local)
	if first != local.Add(-30*time.Second).UnixMilli() || previous != 0 {
		t.Fatalf("timestamp = %d (%d)", first, previous)
	}
	second, _ := clock.timestamp(machine, local)
	if second != first+1 {
		t.Fatalf("timestamps did not increase: %d then %d", first, second)
	}
	clock.withdraw(machine, second, first)
	if third, _ := clock.timestamp(machine, local); third != second {
		t.Fatalf("withdrawn timestamp not reused: %d", third)
	}
	for _, wrong := range []time.Time{time.UnixMilli(0), local.Add(time.Hour), local.Add(-time.Hour)} {
		// ServerHello values far from the estimate are ignored.
		clock.observe(wrong, local, true)
		if clock.offset != -30*time.Second {
			t.Fatalf("Core time %v changed the offset to %v", wrong, clock.offset)
		}
	}
	// The local clock stepped: two ServerHellos that agree move the offset.
	stepped := local.Add(-20 * time.Minute)
	clock.observe(local, stepped, true)
	clock.observe(local.Add(500*time.Millisecond), stepped.Add(500*time.Millisecond), true)
	if clock.offset != 20*time.Minute {
		t.Fatalf("after a clock step the offset is %v", clock.offset)
	}
}

func TestGatewayGateErrorsTemporary(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		message string
		want    error
	}{
		{sharedmtcp.GateProveFirst, controlplane.ErrGatewayProofRequired},
		{sharedmtcp.GateUnavailable, controlplane.ErrRegistrationTemporary},
	} {
		got := gatewayError(&mtcpv1.Error{Code: mtcpv1.Error_NOT_AUTHORIZED, Fatal: true, Message: test.message})
		if !errors.Is(got, test.want) {
			t.Errorf("%q = %v, want %v", test.message, got, test.want)
		}
	}
	if got := gatewayError(&mtcpv1.Error{Code: mtcpv1.Error_NOT_AUTHORIZED, Message: "something else"}); got != nil {
		t.Errorf("an unknown message mapped to %v", got)
	}
}

func TestAdminApprovalOutcomeRefusals(t *testing.T) {
	t.Parallel()
	now := time.Now()
	valid := func() *mtcpv1.RegisterResponse_Pending {
		return &mtcpv1.RegisterResponse_Pending{
			ExpiresMs: now.Add(5 * time.Minute).UnixMilli(),
			AdminApproval: &mtcpv1.RegisterResponse_AdminApproval{
				ClusterId: "01890f90-0000-7000-8000-0000000000c1",
				RequestId: "01890f90-0000-7000-8000-0000000000d1", RequestNonce: make([]byte, 32),
			},
		}
	}
	if _, err := adminApprovalOutcome(valid(), now); err != nil {
		t.Fatalf("a valid approval: %v", err)
	}
	for name, mutate := range map[string]func(*mtcpv1.RegisterResponse_Pending){
		"url too":       func(p *mtcpv1.RegisterResponse_Pending) { p.ApprovalUrl = "https://example.com/register/v1/x" },
		"short nonce":   func(p *mtcpv1.RegisterResponse_Pending) { p.AdminApproval.RequestNonce = make([]byte, 31) },
		"bad cluster":   func(p *mtcpv1.RegisterResponse_Pending) { p.AdminApproval.ClusterId = "prod" },
		"bad request":   func(p *mtcpv1.RegisterResponse_Pending) { p.AdminApproval.RequestId = "request\n1" },
		"expired":       func(p *mtcpv1.RegisterResponse_Pending) { p.ExpiresMs = now.Add(-time.Second).UnixMilli() },
		"no expiry":     func(p *mtcpv1.RegisterResponse_Pending) { p.ExpiresMs = 0 },
		"too far ahead": func(p *mtcpv1.RegisterResponse_Pending) { p.ExpiresMs = now.Add(time.Hour).UnixMilli() },
	} {
		pending := valid()
		mutate(pending)
		if _, err := adminApprovalOutcome(pending, now); !errors.Is(err, controlplane.ErrRegistration) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Each kind of registration takes only its own pending answer.
	approval := &mtcpv1.RegisterResponse{Outcome: &mtcpv1.RegisterResponse_Pending_{Pending: valid()}}
	if _, _, err := registrationOutcome(approval, false, now); err == nil {
		t.Error("an ordinary registration took an admin approval")
	}
	browser := &mtcpv1.RegisterResponse{Outcome: &mtcpv1.RegisterResponse_Pending_{
		Pending: &mtcpv1.RegisterResponse_Pending{ApprovalUrl: "https://example.com/register/v1/x"},
	}}
	if _, _, err := registrationOutcome(browser, true, now); err == nil {
		t.Error("a cluster join took a browser approval")
	}
}

// meshd's client never joins a cluster: its sessions could not prove.
func TestOrdinaryClientRefusesClusterJoin(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	trust := gatewayTrust(t, core)
	_, err := core.client().Register(t.Context(), core.origin(), trust.Material, controlplane.RegisterOptions{
		Hostname: "laptop", PinnedFingerprint: trust.Fingerprint,
		ClusterJoin: &controlplane.ClusterJoin{JoinKey: "mtk1.good"},
	})
	if !errors.Is(err, controlplane.ErrRegistration) {
		t.Fatalf("Register() = %v", err)
	}
}

// meshd's first record is still the Ping, its timestamp its own clock.
func TestOrdinarySessionUnchanged(t *testing.T) {
	t.Parallel()
	core := newFakeCore(t)
	first := make(chan sharedmtcp.MessageType, 4)
	core.set(func(fake *fakeCore) {
		fake.extra = []string{gatewayCapability}
		fake.serve = func(s *coreSession) {
			kind, message, err := s.receive(5 * time.Second)
			if err != nil {
				return
			}
			first <- kind
			if ping, ok := message.(*mtcpv1.Ping); ok {
				_ = s.send(sharedmtcp.MessagePong, &mtcpv1.Pong{Nonce: ping.GetNonce()})
			}
		}
	})
	client := core.client()
	fixed := time.Now().Add(-2 * time.Second)
	client.now = func() time.Time { return fixed }
	trust := gatewayTrust(t, core)
	if err := client.VerifyTrust(t.Context(), core.origin(), trust.Material, trust.Fingerprint); err != nil {
		t.Fatal(err)
	}
	if kind := <-first; kind != sharedmtcp.MessagePing {
		t.Fatalf("first record %#x", uint8(kind))
	}
	hellos, _ := core.sessions()
	if got := hellos[len(hellos)-1].GetTimestampMs(); got != fixed.UnixMilli() {
		t.Fatalf("hello timestamp %d, want the client's own %d", got, fixed.UnixMilli())
	}
}

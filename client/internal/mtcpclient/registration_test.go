package mtcpclient

import (
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// registrationCore answers RegisterRequests: enrollment keys are accepted
// when they equal goodKey; interactive requests wait for approved.
type registrationCore struct {
	*fakeCore
	goodKey  string
	approved atomic.Bool
	approve  atomic.Int64 // approve this many nanoseconds into a follow-up's wait
	requests atomic.Int32
}

func newRegistrationCore(t *testing.T) *registrationCore {
	core := &registrationCore{fakeCore: newFakeCore(t), goodKey: "mtc1.good"}
	core.set(func(fake *fakeCore) { fake.serve = core.handleRegistration })
	return core
}

func (core *registrationCore) approvalURL() string { return core.origin() + approvalPath + "token-1" }

func (core *registrationCore) handleRegistration(s *coreSession) {
	_, message, err := s.receive(5 * time.Second)
	if err != nil {
		return
	}
	request, ok := message.(*mtcpv1.RegisterRequest)
	if !ok {
		return
	}
	core.requests.Add(1)
	if !sharedmtcp.VerifyKeyProof(s.control, s.hash, [32]byte(request.GetNodeKey()), request.GetNodeKeyProof()) ||
		!sharedmtcp.VerifyKeyProof(s.control, s.hash, [32]byte(request.GetDiscoKey()), request.GetDiscoKeyProof()) ||
		string(request.GetNodeKey()) != string(s.hello.GetNodeKey()) || request.GetHostinfo().GetHostname() != "laptop" {
		core.respond(s, &mtcpv1.RegisterResponse{Outcome: &mtcpv1.RegisterResponse_Rejected_{
			Rejected: &mtcpv1.RegisterResponse_Rejected{Code: mtcpv1.RegisterResponse_Rejected_INVALID},
		}})
		return
	}
	switch method := request.GetAuth().GetMethod().(type) {
	case *mtcpv1.RegisterRequest_Auth_EnrollmentKey:
		if method.EnrollmentKey != core.goodKey {
			core.respond(s, &mtcpv1.RegisterResponse{Outcome: &mtcpv1.RegisterResponse_Rejected_{
				Rejected: &mtcpv1.RegisterResponse_Rejected{
					Code:    mtcpv1.RegisterResponse_Rejected_CREDENTIAL_INVALID,
					Message: "the enrollment key is not valid",
				},
			}})
			return
		}
		core.authorize(s)
	case *mtcpv1.RegisterRequest_Auth_Interactive:
		handle := method.Interactive.GetResumeHandle()
		if handle != "" && handle != "token-1" {
			core.respond(s, &mtcpv1.RegisterResponse{Outcome: &mtcpv1.RegisterResponse_Rejected_{
				Rejected: &mtcpv1.RegisterResponse_Rejected{Code: mtcpv1.RegisterResponse_Rejected_EXPIRED},
			}})
			return
		}
		if handle != "" && core.approved.Load() {
			core.authorize(s)
			return
		}
		core.respond(s, &mtcpv1.RegisterResponse{Outcome: &mtcpv1.RegisterResponse_Pending_{
			Pending: &mtcpv1.RegisterResponse_Pending{
				ApprovalUrl: core.approvalURL(), ResumeHandle: "token-1",
				ExpiresMs: time.Now().Add(10 * time.Minute).UnixMilli(),
			},
		}})
		if wait := time.Duration(core.approve.Load()); wait > 0 {
			time.Sleep(wait)
			core.authorize(s)
			return
		}
		answerPings(s)
	}
}

func (core *registrationCore) respond(s *coreSession, response *mtcpv1.RegisterResponse) {
	_ = s.send(sharedmtcp.MessageRegisterResponse, response)
}

func (core *registrationCore) authorize(s *coreSession) {
	core.respond(s, &mtcpv1.RegisterResponse{Outcome: &mtcpv1.RegisterResponse_Authorized_{
		Authorized: &mtcpv1.RegisterResponse_Authorized{DeviceId: "device"},
	}})
	_ = s.send(sharedmtcp.MessageKeyUpdate, &mtcpv1.KeyUpdate{})
	answerPings(s)
}

func (core *registrationCore) trust(t *testing.T) controlplane.TrustResult {
	t.Helper()
	var serve func(*coreSession)
	core.set(func(fake *fakeCore) { serve, fake.serve = fake.serve, answerPings })
	trust, err := core.client().BootstrapTrust(t.Context(), core.origin(),
		controlplane.ControlKeyFingerprint(core.controlKey().Public()))
	core.set(func(fake *fakeCore) { fake.serve = serve })
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

func TestRegisterWithEnrollmentKey(t *testing.T) {
	t.Parallel()
	core := newRegistrationCore(t)
	trust := core.trust(t)
	options := controlplane.RegisterOptions{
		Hostname: "laptop", Version: "meshd/test",
		PinnedFingerprint: trust.Fingerprint, AuthKey: "mtc1.good",
	}
	result, err := core.client().Register(t.Context(), core.origin(), trust.Material, options)
	if err != nil || result.State != controlplane.RegistrationStateAuthorized || !result.MachineAuthorized {
		t.Fatalf("Register = %+v, %v", result, err)
	}
	options.AuthKey = "mtc1.bad"
	if _, err := core.client().Register(t.Context(), core.origin(), trust.Material, options); !errors.Is(err,
		controlplane.ErrRegistration) || errors.Is(err, controlplane.ErrRegistrationTemporary) ||
		!strings.Contains(err.Error(), "credential_invalid") {
		t.Fatalf("bad key: %v", err)
	}
	options.PinnedFingerprint = controlplane.ControlKeyFingerprint([32]byte{3})
	options.AuthKey = "mtc1.good"
	before := core.requests.Load()
	if _, err := core.client().Register(t.Context(), core.origin(), trust.Material, options); !errors.Is(err,
		controlplane.ErrControlKeyChanged) || core.requests.Load() != before {
		t.Fatalf("another pin: %v (a request must not be sent)", err)
	}
}

func TestRegisterInteractively(t *testing.T) {
	t.Parallel()
	core := newRegistrationCore(t)
	trust := core.trust(t)
	options := controlplane.RegisterOptions{Hostname: "laptop", PinnedFingerprint: trust.Fingerprint}
	started := time.Now()
	result, err := core.client().Register(t.Context(), core.origin(), trust.Material, options)
	if err != nil || result.State != controlplane.RegistrationStateAuthorizationRequired ||
		result.AuthURL != core.approvalURL() {
		t.Fatalf("first Register = %+v, %v", result, err)
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("a new approval must be reported at once")
	}
	// A follow-up waits on its session: an approval during the wait
	// authorizes without another request.
	core.approve.Store(int64(100 * time.Millisecond))
	options.FollowupURL = result.AuthURL
	result, err = core.client().Register(t.Context(), core.origin(), trust.Material, options)
	if err != nil || result.State != controlplane.RegistrationStateAuthorized {
		t.Fatalf("follow-up = %+v, %v", result, err)
	}
	core.approve.Store(0)
	core.approved.Store(true)
	if result, err = core.client().Register(t.Context(), core.origin(), trust.Material, options); err != nil ||
		result.State != controlplane.RegistrationStateAuthorized {
		t.Fatalf("follow-up after approval = %+v, %v", result, err)
	}
	for name, followup := range map[string]string{
		"other host":   "https://evil.example" + approvalPath + "token-1",
		"other path":   core.origin() + "/elsewhere/token-1",
		"with a query": core.approvalURL() + "?x=1",
	} {
		options.FollowupURL = followup
		if _, err := core.client().Register(t.Context(), core.origin(), trust.Material, options); !errors.Is(err,
			controlplane.ErrRegistration) {
			t.Errorf("%s: %v", name, err)
		}
	}
	options.FollowupURL = core.origin() + approvalPath + "token-2"
	if _, err := core.client().Register(t.Context(), core.origin(), trust.Material, options); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("unknown handle: %v", err)
	}
}

func TestRotateNodeKey(t *testing.T) {
	t.Parallel()
	core := newRegistrationCore(t)
	trust := core.trust(t)
	newKey, err := controlplane.GenerateNodePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	newRaw, _ := controlplane.ParsePrivateKey(newKey)
	newNode, _ := key.NodePrivateFromBytes(newRaw[:])
	newPublic := newNode.Public()
	var fail atomic.Bool
	rotationCore := func(s *coreSession) {
		if _, first, err := s.receive(5 * time.Second); err != nil || first == nil {
			return
		} else if _, ok := first.(*mtcpv1.Ping); !ok {
			return // Core would not establish the session
		}
		_ = s.send(sharedmtcp.MessageMapSnapshot, &mtcpv1.MapSnapshot{View: &mtcpv1.View{Epoch: 1, Seq: 1}})
		for {
			_, message, err := s.receive(5 * time.Second)
			if err != nil {
				return
			}
			rotate, ok := message.(*mtcpv1.RotateNodeKey)
			if !ok {
				continue
			}
			if fail.Load() {
				_ = s.send(sharedmtcp.MessageError, &mtcpv1.Error{Code: mtcpv1.Error_NOT_AUTHORIZED})
				return
			}
			if !sharedmtcp.VerifyKeyProof(s.control, s.hash, [32]byte(rotate.GetNewNodeKey()), rotate.GetNodeKeyProof()) ||
				string(rotate.GetNewNodeKey()) != string(newPublic[:]) {
				_ = s.send(sharedmtcp.MessageError, &mtcpv1.Error{Code: mtcpv1.Error_INVALID})
				return
			}
			_ = s.send(sharedmtcp.MessageRotateNodeKeyResponse, &mtcpv1.RotateNodeKeyResponse{NodeKey: rotate.GetNewNodeKey()})
			answerPings(s)
			return
		}
	}
	core.set(func(fake *fakeCore) { fake.serve = rotationCore })
	options := controlplane.RegisterOptions{Hostname: "laptop", PinnedFingerprint: trust.Fingerprint}
	result, err := core.client().RotateNodeKey(t.Context(), core.origin(), trust.Material, newKey, options)
	if err != nil || result.State != controlplane.RegistrationStateAuthorized {
		t.Fatalf("RotateNodeKey = %+v, %v", result, err)
	}
	hellos, _ := core.sessions()
	oldRaw, _ := controlplane.ParsePrivateKey(trust.Material.NodePrivateKey)
	oldNode, _ := key.NodePrivateFromBytes(oldRaw[:])
	oldPublic := oldNode.Public()
	if last := hellos[len(hellos)-1]; string(last.GetNodeKey()) != string(oldPublic[:]) {
		t.Fatal("the rotation session must be opened by the current node key")
	}
	fail.Store(true)
	_, err = core.client().RotateNodeKey(t.Context(), core.origin(), trust.Material, newKey, options)
	if !errors.Is(err, controlplane.ErrRegistration) || errors.Is(err, controlplane.ErrRegistrationTemporary) {
		t.Fatalf("refused rotation: %v", err)
	}
}

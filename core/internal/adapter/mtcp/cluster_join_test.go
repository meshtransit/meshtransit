package mtcp

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/ipam"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const testJoinKey = "mtk1.01890f90-0000-7000-8000-000000000001.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"

// fakeClusterJoins opens one request per attempt in the state it is told,
// and completes it once complete() is called.
type fakeClusterJoins struct {
	mu          sync.Mutex
	scope       network.Scope
	result      registration.Result
	openErr     error
	openState   kubecluster.RequestState
	expiresAt   time.Time
	deadline    time.Time // an approved request's completion deadline; zero: expiresAt
	completed   bool
	completeErr error
	attempts    []kubecluster.JoinAttempt
	checks      []kubecluster.RequestID
}

func (joins *fakeClusterJoins) OpenReplicaRequest(_ context.Context, attempt kubecluster.JoinAttempt) (
	kubecluster.JoinTicket, error) {
	joins.mu.Lock()
	defer joins.mu.Unlock()
	joins.attempts = append(joins.attempts, attempt)
	if joins.openErr != nil {
		return kubecluster.JoinTicket{}, joins.openErr
	}
	lifecycle, err := kubecluster.NewRequest(kubecluster.RequestParams{State: joins.openState,
		CreatedAt: joins.expiresAt.Add(-time.Hour), ExpiresAt: joins.expiresAt})
	if err != nil {
		return kubecluster.JoinTicket{}, err
	}
	params := kubecluster.ReplicaRequestParams{ID: attempt.RequestID, ClusterID: testClusterID,
		KeyID: attempt.Presentation.CredentialID(), MachineFingerprint: hexFingerprint(attempt.MachineKey.Fingerprint()),
		NodeFingerprint: hexFingerprint(attempt.NodeKey.Fingerprint()), Hostname: attempt.Hostname.String(),
		Reported: attempt.Reported, Lifecycle: lifecycle, Version: 1, UpdatedAt: joins.expiresAt.Add(-time.Hour)}
	if joins.openState != kubecluster.RequestPending {
		params.ApprovedBy, params.ApprovedAt = testApprover, joins.expiresAt.Add(-time.Hour)
		params.CompletionDeadline, params.ReservedHostname = joins.expiresAt, "prod-0"
		if !joins.deadline.IsZero() {
			params.CompletionDeadline = joins.deadline
		}
	}
	if joins.openState == kubecluster.RequestCompleted {
		params.DeviceID = joins.result.NodeID()
	}
	view, err := kubecluster.NewReplicaRequestView(params)
	if err != nil {
		return kubecluster.JoinTicket{}, err
	}
	return kubecluster.JoinTicket{Request: view, ClusterID: testClusterID, Scope: joins.scope,
		Nonce: attempt.Nonce, Created: true}, nil
}

func (joins *fakeClusterJoins) CompleteReplicaRequest(_ context.Context, scope network.Scope,
	requestID kubecluster.RequestID, identity node.RegistrationIdentity) (kubecluster.Completion, error) {
	joins.mu.Lock()
	defer joins.mu.Unlock()
	joins.checks = append(joins.checks, requestID)
	if scope != joins.scope || !identity.IsValid() || len(joins.attempts) == 0 ||
		joins.attempts[len(joins.attempts)-1].RequestID != requestID ||
		identity.NodeKey() != joins.attempts[len(joins.attempts)-1].NodeKey {
		return kubecluster.Completion{}, kubecluster.ErrNotFound
	}
	if joins.completeErr != nil {
		return kubecluster.Completion{}, joins.completeErr
	}
	if !joins.completed && joins.openState != kubecluster.RequestCompleted {
		return kubecluster.Completion{State: kubecluster.RequestPending}, nil
	}
	return kubecluster.Completion{State: kubecluster.RequestCompleted, Result: joins.result}, nil
}

func hexFingerprint(fingerprint [32]byte) string { return hex.EncodeToString(fingerprint[:]) }

func (joins *fakeClusterJoins) complete() {
	joins.mu.Lock()
	defer joins.mu.Unlock()
	joins.completed = true
}

func (joins *fakeClusterJoins) fail(err error) {
	joins.mu.Lock()
	defer joins.mu.Unlock()
	joins.completeErr = err
}

func (joins *fakeClusterJoins) opened() []kubecluster.JoinAttempt {
	joins.mu.Lock()
	defer joins.mu.Unlock()
	return append([]kubecluster.JoinAttempt(nil), joins.attempts...)
}

func (joins *fakeClusterJoins) checked() int {
	joins.mu.Lock()
	defer joins.mu.Unlock()
	return len(joins.checks)
}

var (
	testClusterID = must(kubecluster.ParseID("01890f90-0000-7000-8000-0000000000c1"))
	testApprover  = must(identity.ParsePrincipalID("01890f90-0000-7000-8000-0000000000a1"))
)

// fixedJoinSecrets proposes one request ID and nonce.
type fixedJoinSecrets struct{}

func (fixedJoinSecrets) NewRequestID() (kubecluster.RequestID, error) {
	return kubecluster.ParseRequestID("01890f90-0000-7000-8000-0000000000d1")
}

func (fixedJoinSecrets) NewRequestNonce() ([32]byte, error) {
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	return nonce, nil
}

func clusterJoinAuth(joinKey string, reported []byte) *mtcpv1.RegisterRequest_Auth {
	return &mtcpv1.RegisterRequest_Auth{Method: &mtcpv1.RegisterRequest_Auth_ClusterJoin{
		ClusterJoin: &mtcpv1.RegisterRequest_ClusterJoin{JoinKey: joinKey, Reported: reported}}}
}

func TestClusterJoinWaitsForApproval(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.clusterJoins.expiresAt = f.now().Add(time.Hour)
	f.run()
	request := f.request(4, clusterJoinAuth(testJoinKey, []byte(`{"pod": "meshgw-0", "namespace":"mt"}`)))
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, request); err != nil {
		t.Fatal(err)
	}
	pending := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetPending()
	nonce := must(fixedJoinSecrets{}.NewRequestNonce())
	approval := pending.GetAdminApproval()
	if pending.GetApprovalUrl() != "" || pending.GetResumeHandle() != "" ||
		pending.GetExpiresMs() != f.now().Add(10*time.Minute).UnixMilli() ||
		approval.GetClusterId() != testClusterID.String() ||
		approval.GetRequestId() != "01890f90-0000-7000-8000-0000000000d1" ||
		string(approval.GetRequestNonce()) != string(nonce[:]) {
		t.Fatalf("pending %v", pending)
	}
	attempts := f.clusterJoins.opened()
	if len(attempts) != 1 {
		t.Fatalf("%d attempts", len(attempts))
	}
	attempt := attempts[0]
	if !attempt.IsValid() || attempt.MachineKey.Bytes() != [32]byte(f.session.Machine()) ||
		attempt.NodeKey != node.Key(request.GetNodeKey()) || attempt.Hostname.String() != "laptop" ||
		string(attempt.Reported) != `{"namespace":"mt","pod":"meshgw-0"}` || attempt.Nonce != nonce ||
		attempt.Presentation.Reveal() != testJoinKey {
		t.Fatalf("attempt %+v", attempt)
	}
	// Nothing happens until the approval; then Core answers on its own.
	select {
	case <-f.streams.started:
		t.Fatal("a stream started before the approval")
	case <-time.After(30 * time.Millisecond):
	}
	f.clusterJoins.complete()
	f.expectStream(node.Key(request.GetNodeKey()))
	if f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetAuthorized() == nil {
		t.Fatal("no authorized response after the approval")
	}
}

// The request waits no longer than its key lives.
func TestClusterJoinWaitEndsWithTheKey(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.clusterJoins.expiresAt = f.now().Add(3 * time.Minute)
	f.run()
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest,
		f.request(4, clusterJoinAuth(testJoinKey, nil))); err != nil {
		t.Fatal(err)
	}
	pending := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetPending()
	if pending.GetExpiresMs() != f.now().Add(3*time.Minute).UnixMilli() {
		t.Fatalf("pending %v", pending)
	}
	if got := string(f.clusterJoins.opened()[0].Reported); got != "{}" {
		t.Fatalf("no report stored as %q", got)
	}
	// Past expires_ms Core stops checking without answering: the node asks
	// again with the same key and keys (mtcp-v1 §6.6).
	f.advance(3 * time.Minute)
	time.Sleep(30 * time.Millisecond)
	checks := f.clusterJoins.checked()
	time.Sleep(30 * time.Millisecond)
	if f.clusterJoins.checked() != checks {
		t.Fatal("Core still checks a request past expires_ms")
	}
	if kind, message, ok := f.node.read(); ok {
		t.Fatalf("Core answered %#x %v after expires_ms", uint8(kind), message)
	}
}

// An approved request waits until its completion deadline, not its key's
// end.
func TestClusterJoinApprovedWaitsForItsDeadline(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.clusterJoins.openState = kubecluster.RequestApproved
	f.clusterJoins.expiresAt, f.clusterJoins.deadline = f.now().Add(time.Minute), f.now().Add(5*time.Minute)
	f.run()
	request := f.request(4, clusterJoinAuth(testJoinKey, nil))
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, request); err != nil {
		t.Fatal(err)
	}
	pending := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetPending()
	if pending.GetExpiresMs() != f.now().Add(5*time.Minute).UnixMilli() {
		t.Fatalf("pending %v", pending)
	}
	f.clusterJoins.complete()
	f.expectStream(node.Key(request.GetNodeKey()))
	if f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetAuthorized() == nil {
		t.Fatal("no authorized response once completed")
	}
}

// A replica that asks again after its request completed gets its Device.
func TestClusterJoinResumesACompletedRequest(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.clusterJoins.openState = kubecluster.RequestCompleted
	f.clusterJoins.expiresAt = f.now().Add(time.Hour)
	f.run()
	request := f.request(4, clusterJoinAuth(testJoinKey, nil))
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, request); err != nil {
		t.Fatal(err)
	}
	f.expectStream(node.Key(request.GetNodeKey()))
	if f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetAuthorized() == nil {
		t.Fatal("a completed request did not authorize")
	}
}

func TestClusterJoinRefusals(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		joinKey  string
		reported []byte
		openErr  error
		want     mtcpv1.RegisterResponse_Rejected_Code
		opened   bool // the store saw the attempt
	}{
		{name: "malformed key", joinKey: "mtk1.nope", want: mtcpv1.RegisterResponse_Rejected_CREDENTIAL_INVALID},
		{name: "enrollment key", joinKey: testEnrollmentKey, want: mtcpv1.RegisterResponse_Rejected_CREDENTIAL_INVALID},
		{name: "nested report", reported: []byte(`{"pod":{"name":"x"}}`), want: mtcpv1.RegisterResponse_Rejected_INVALID},
		{name: "report not JSON", reported: []byte(`pod=x`), want: mtcpv1.RegisterResponse_Rejected_INVALID},
		{name: "wrong secret", openErr: kubecluster.ErrJoinRefused, opened: true,
			want: mtcpv1.RegisterResponse_Rejected_CREDENTIAL_INVALID},
		{name: "key used up", openErr: kubecluster.ErrKeyNotUsable, opened: true,
			want: mtcpv1.RegisterResponse_Rejected_CREDENTIAL_EXHAUSTED},
		{name: "keys in use", openErr: kubecluster.ErrKeysInUse, opened: true,
			want: mtcpv1.RegisterResponse_Rejected_CONFLICT},
		{name: "queue full", openErr: kubecluster.ErrQueueFull, opened: true,
			want: mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
			f.clusterJoins.openErr, f.clusterJoins.expiresAt = test.openErr, f.now().Add(time.Hour)
			f.run()
			joinKey := test.joinKey
			if joinKey == "" {
				joinKey = testJoinKey
			}
			if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest,
				f.request(4, clusterJoinAuth(joinKey, test.reported))); err != nil {
				t.Fatal(err)
			}
			if got := len(f.clusterJoins.opened()) == 1; got != test.opened {
				t.Fatalf("store saw the attempt: %t, want %t", got, test.opened)
			}
			if got := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetRejected().
				GetCode(); got != test.want {
				t.Fatalf("rejected %v, want %v", got, test.want)
			}
		})
	}
}

// A join key is never an enrollment key.
func TestJoinKeyIsNotAnEnrollmentKey(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.run()
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest,
		f.request(4, enrollmentAuth(testJoinKey))); err != nil {
		t.Fatal(err)
	}
	if len(f.registrations.calls()) != 0 {
		t.Fatal("a join key reached enrollment")
	}
	if got := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetRejected().GetCode(); got !=
		mtcpv1.RegisterResponse_Rejected_CREDENTIAL_INVALID {
		t.Fatalf("rejected %v", got)
	}
}

func TestClusterJoinStoreFailureIsAnError(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.clusterJoins.openErr = kubecluster.ErrUnavailable
	f.run()
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest,
		f.request(4, clusterJoinAuth(testJoinKey, nil))); err != nil {
		t.Fatal(err)
	}
	if got := f.expect(sharedmtcp.MessageError).(*mtcpv1.Error); got.GetCode() != mtcpv1.Error_INTERNAL ||
		got.GetRetryAfterMs() == 0 {
		t.Fatalf("error %v", got)
	}
}

// What ends a request while its session waits is answered once.
func TestClusterJoinAnswersEndedRequests(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		err     error
		want    mtcpv1.RegisterResponse_Rejected_Code
		message string
	}{
		{err: kubecluster.ErrNotWaiting, want: mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED},
		{err: kubecluster.ErrKeyNotUsable, want: mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED},
		{err: kubecluster.ErrNotFound, want: mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED},
		{err: kubecluster.ErrExpired, want: mtcpv1.RegisterResponse_Rejected_EXPIRED},
		{err: errors.Join(errors.New("allocation"), ipam.ErrAddressExhausted),
			want: mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED, message: networkFull.message},
	} {
		f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
		f.clusterJoins.expiresAt = f.now().Add(time.Hour)
		f.run()
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest,
			f.request(4, clusterJoinAuth(testJoinKey, nil))); err != nil {
			t.Fatal(err)
		}
		f.expect(sharedmtcp.MessageRegisterResponse)
		f.clusterJoins.fail(test.err)
		rejected := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetRejected()
		if rejected.GetCode() != test.want || test.message != "" && rejected.GetMessage() != test.message {
			t.Fatalf("%v answered %v", test.err, rejected)
		}
		checks := f.clusterJoins.checked()
		time.Sleep(30 * time.Millisecond)
		if f.clusterJoins.checked() != checks {
			t.Fatalf("%v: Core still checks an ended request", test.err)
		}
	}
}

// A transient failure is checked again on the next tick.
func TestClusterJoinRetriesTransientFailures(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.clusterJoins.expiresAt = f.now().Add(time.Hour)
	f.run()
	request := f.request(4, clusterJoinAuth(testJoinKey, nil))
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, request); err != nil {
		t.Fatal(err)
	}
	f.expect(sharedmtcp.MessageRegisterResponse)
	f.clusterJoins.fail(kubecluster.ErrConflict)
	checks := f.clusterJoins.checked()
	for f.clusterJoins.checked() < checks+2 {
		time.Sleep(5 * time.Millisecond)
	}
	f.clusterJoins.fail(nil)
	f.clusterJoins.complete()
	f.expectStream(node.Key(request.GetNodeKey()))
	if f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetAuthorized() == nil {
		t.Fatal("no authorized response after a transient failure")
	}
}

// A deployment without cluster joins refuses them before any lookup.
func TestClusterJoinDisabled(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.talk.application.options.ClusterJoins, f.talk.application.options.ClusterJoinSecrets = nil, nil
	f.run()
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest,
		f.request(4, clusterJoinAuth(testJoinKey, nil))); err != nil {
		t.Fatal(err)
	}
	if len(f.clusterJoins.opened()) != 0 {
		t.Fatal("a disabled deployment opened a request")
	}
	if got := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetRejected().GetCode(); got !=
		mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED {
		t.Fatalf("rejected %v", got)
	}
}

// Opening requests writes the database: it spends the browser budget.
func TestClusterJoinIsRateLimited(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.clusterJoins.openErr = kubecluster.ErrJoinRefused
	f.run()
	for range browserBurst {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest,
			f.request(4, clusterJoinAuth(testJoinKey, nil))); err != nil {
			t.Fatal(err)
		}
		f.expect(sharedmtcp.MessageRegisterResponse)
	}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest,
		f.request(4, clusterJoinAuth(testJoinKey, nil))); err != nil {
		t.Fatal(err)
	}
	if got := f.expect(sharedmtcp.MessageError).(*mtcpv1.Error); got.GetCode() != mtcpv1.Error_OVERLOADED {
		t.Fatalf("error %v", got)
	}
	if got := len(f.clusterJoins.opened()); got != browserBurst {
		t.Fatalf("%d attempts reached the store", got)
	}
}

// The session that completed a join serves its gateway with the node key
// it proved, and the gateway neither registers again nor logs out.
func TestCompletedJoinIsAProvenGateway(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.clusterJoins.openState = kubecluster.RequestCompleted
	f.clusterJoins.expiresAt = f.now().Add(time.Hour)
	f.run()
	request := f.request(4, clusterJoinAuth(testJoinKey, nil))
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, request); err != nil {
		t.Fatal(err)
	}
	f.expectStream(node.Key(request.GetNodeKey()))
	f.expectPast(sharedmtcp.MessageRegisterResponse)
	if proven := f.streams.provenStreams(); len(proven) != 1 || !proven[0] {
		t.Fatalf("streams proven %v", proven)
	}
	assertGatewayRefusesRegistrationAndLogout(t, f)
}

// A session that proved a gateway's node key at its start (§6.7).
func TestProvenGatewaySession(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	helloKey := node.Key(f.session.Hello().GetNodeKey())
	f.session.gate = TimestampCheck{Accepted: true, Gateway: true, Machine: MachineCurrent, NodeCurrent: true}
	f.session.provenNodeKey = helloKey
	f.talk = f.talk.application.Open(f.session).(*conversation)
	f.run()
	f.expectStream(helloKey)
	if proven := f.streams.provenStreams(); len(proven) != 1 || !proven[0] {
		t.Fatalf("streams proven %v", proven)
	}
	f.expect(sharedmtcp.MessageKeyUpdate)
	f.expect(sharedmtcp.MessageMapSnapshot)
	assertGatewayRefusesRegistrationAndLogout(t, f)
}

func assertGatewayRefusesRegistrationAndLogout(t *testing.T, f *conversationFixture) {
	t.Helper()
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest,
		f.request(9, enrollmentAuth(testEnrollmentKey))); err != nil {
		t.Fatal(err)
	}
	if got := f.expectPast(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetRejected().GetCode(); got !=
		mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED || len(f.registrations.calls()) != 0 {
		t.Fatalf("a gateway registered again: %v", got)
	}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageLogout, &mtcpv1.Logout{}); err != nil {
		t.Fatal(err)
	}
	if got := f.expectPast(sharedmtcp.MessageError).(*mtcpv1.Error); got.GetCode() != mtcpv1.Error_NOT_PERMITTED {
		t.Fatalf("logout answered %v", got)
	}
	f.logout.mu.Lock()
	defer f.logout.mu.Unlock()
	if len(f.logout.keys) != 0 {
		t.Fatal("a gateway's logout reached the store")
	}
}

// expectPast returns the next message of type want, past the map and key
// messages a starting stream sends.
func (f *conversationFixture) expectPast(want sharedmtcp.MessageType) any {
	f.t.Helper()
	for {
		kind, message := f.next()
		switch kind {
		case want:
			return message
		case sharedmtcp.MessageKeyUpdate, sharedmtcp.MessageMapSnapshot, sharedmtcp.MessageRegisterResponse:
		default:
			f.t.Fatalf("got %#x %v, want %#x", uint8(kind), message, uint8(want))
		}
	}
}

// An ordinary Device's streams carry no proof mark, even after it proved
// its key registering: only gateways need it (no extra statement).
func TestOrdinaryRegistrationIsNotMarked(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.run()
	request := f.request(9, enrollmentAuth(testEnrollmentKey))
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, request); err != nil {
		t.Fatal(err)
	}
	f.expectStream(node.Key(request.GetNodeKey()))
	if proven := f.streams.provenStreams(); len(proven) != 1 || proven[0] {
		t.Fatalf("streams proven %v", proven)
	}
}

// fakeMachineKeyRotations records rotations and fails with err when set.
type fakeMachineKeyRotations struct {
	mu        sync.Mutex
	err       error
	rotations []kubecluster.MachineKeyRotation
	// during, when set, runs while the rotation commits.
	during func()
}

func (rotations *fakeMachineKeyRotations) RotateGatewayMachineKey(_ context.Context,
	rotation kubecluster.MachineKeyRotation) error {
	if rotations.during != nil {
		rotations.during()
	}
	rotations.mu.Lock()
	defer rotations.mu.Unlock()
	rotations.rotations = append(rotations.rotations, rotation)
	return rotations.err
}

func (rotations *fakeMachineKeyRotations) calls() []kubecluster.MachineKeyRotation {
	rotations.mu.Lock()
	defer rotations.mu.Unlock()
	return slices.Clone(rotations.rotations)
}

// gatewayFixture is a session that proved a gateway's node key.
func gatewayFixture(t *testing.T, rotations *fakeMachineKeyRotations) *conversationFixture {
	t.Helper()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	f.session.gate = TimestampCheck{Accepted: true, Gateway: true, Machine: MachineCurrent, NodeCurrent: true}
	f.session.provenNodeKey = node.Key(f.session.Hello().GetNodeKey())
	f.talk.application.options.MachineKeyRotations = rotations
	f.talk.application.options.GatewayPresence = &fakeGatewayPresence{state: mapsession.GatewayRotationHeld}
	f.talk.application.gatewayClaimWait = 200 * time.Millisecond
	if err := f.session.server.establish(f.session); err != nil {
		t.Fatal(err)
	}
	f.talk = f.talk.application.Open(f.session).(*conversation)
	return f
}

func (f *conversationFixture) rotateMachineKey(seed byte, proofSeed byte) (*mtcpv1.RotateMachineKey, error) {
	f.t.Helper()
	next := must(key.MachinePrivateFromBytes(repeat(seed, key.Size)))
	prover := must(key.MachinePrivateFromBytes(repeat(proofSeed, key.Size)))
	proof := must(sharedmtcp.MachineKeyRotationProof(prover, f.control.Public(), f.session.HandshakeHash()))
	public := next.Public()
	request := &mtcpv1.RotateMachineKey{NewMachineKey: public[:], Proof: proof[:]}
	return request, f.talk.Receive(f.t.Context(), sharedmtcp.MessageRotateMachineKey, request)
}

func TestGatewayRotatesItsMachineKey(t *testing.T) {
	t.Parallel()
	rotations := &fakeMachineKeyRotations{}
	f := gatewayFixture(t, rotations)
	f.run()
	request, err := f.rotateMachineKey(0x44, 0x44)
	if !errors.Is(err, errMachineKeyRotated) {
		t.Fatalf("Receive() = %v, want the session to end", err)
	}
	f.expectPast(sharedmtcp.MessageRotateMachineKeyResponse)
	calls := rotations.calls()
	if len(calls) != 1 || calls[0].NewMachineKey != node.MachineKey(request.GetNewMachineKey()) ||
		calls[0].MachineKey != node.MachineKey(f.session.Machine()) ||
		calls[0].NodeKey != node.Key(f.session.Hello().GetNodeKey()) || !calls[0].OperationID.IsValid() {
		t.Fatalf("rotations %+v", calls)
	}
}

func TestMachineKeyRotationRefusals(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		gateway   bool
		proofSeed byte
		err       error
		code      mtcpv1.Error_Code
		stored    bool
	}{
		{name: "not a gateway", proofSeed: 0x44, code: mtcpv1.Error_NOT_PERMITTED},
		{name: "wrong proof", gateway: true, proofSeed: 0x45, code: mtcpv1.Error_INVALID},
		{name: "key used before", gateway: true, proofSeed: 0x44, err: kubecluster.ErrMachineKeyUsed,
			code: mtcpv1.Error_NOT_PERMITTED, stored: true},
		{name: "over the budget", gateway: true, proofSeed: 0x44,
			err: &kubecluster.RotationLimitedError{RetryAfter: time.Minute}, code: mtcpv1.Error_NOT_PERMITTED,
			stored: true},
		{name: "keys no longer current", gateway: true, proofSeed: 0x44, err: kubecluster.ErrNotFound,
			code: mtcpv1.Error_NOT_AUTHORIZED, stored: true},
		{name: "store unavailable", gateway: true, proofSeed: 0x44, err: kubecluster.ErrUnavailable,
			code: mtcpv1.Error_INTERNAL, stored: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			rotations := &fakeMachineKeyRotations{err: test.err}
			var f *conversationFixture
			if test.gateway {
				f = gatewayFixture(t, rotations)
			} else {
				f = newConversationFixture(t, sharedmtcp.MessagePing)
				f.talk.application.options.MachineKeyRotations = rotations
			}
			f.run()
			if _, err := f.rotateMachineKey(0x44, test.proofSeed); err != nil {
				t.Fatalf("Receive() = %v", err)
			}
			if got := f.expectPast(sharedmtcp.MessageError).(*mtcpv1.Error); got.GetCode() != test.code ||
				got.GetFatal() {
				t.Fatalf("answered %v", got)
			}
			if stored := len(rotations.calls()) == 1; stored != test.stored {
				t.Fatalf("store called: %t, want %t", stored, test.stored)
			}
		})
	}
}

// A gateway session that has not proved its node key does not rotate, nor
// does a key spelled with bit 255 set; a refusal resumes the map stream.
func TestMachineKeyRotationNeedsAProvenKeyAndResumes(t *testing.T) {
	t.Parallel()
	rotations := &fakeMachineKeyRotations{err: kubecluster.ErrMachineKeyUsed}
	unproven := gatewayFixture(t, rotations)
	unproven.talk.provenNodeKey = node.Key{}
	unproven.run()
	if _, err := unproven.rotateMachineKey(0x44, 0x44); err != nil {
		t.Fatal(err)
	}
	if got := unproven.expectPast(sharedmtcp.MessageError).(*mtcpv1.Error); got.GetCode() != mtcpv1.Error_NOT_AUTHORIZED {
		t.Fatalf("unproven answered %v", got)
	}
	if len(rotations.calls()) != 0 {
		t.Fatal("an unproven session reached the store")
	}

	f := gatewayFixture(t, rotations)
	helloKey := node.Key(f.session.Hello().GetNodeKey())
	f.run()
	f.expectStream(helloKey)
	next := must(key.MachinePrivateFromBytes(repeat(0x46, key.Size)))
	public := next.Public()
	spelled := append([]byte(nil), public[:]...)
	spelled[key.Size-1] |= 0x80
	proof := must(sharedmtcp.MachineKeyRotationProof(next, f.control.Public(), f.session.HandshakeHash()))
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRotateMachineKey,
		&mtcpv1.RotateMachineKey{NewMachineKey: spelled, Proof: proof[:]}); err != nil {
		t.Fatal(err)
	}
	if got := f.expectPast(sharedmtcp.MessageError).(*mtcpv1.Error); got.GetCode() != mtcpv1.Error_INVALID {
		t.Fatalf("a second spelling answered %v", got)
	}
	if _, err := f.rotateMachineKey(0x44, 0x44); err != nil {
		t.Fatal(err)
	}
	if got := f.expectPast(sharedmtcp.MessageError).(*mtcpv1.Error); got.GetCode() != mtcpv1.Error_NOT_PERMITTED {
		t.Fatalf("a used key answered %v", got)
	}
	f.expectStream(helloKey) // resumed after the refusal
}

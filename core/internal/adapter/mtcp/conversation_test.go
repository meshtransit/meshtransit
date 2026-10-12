package mtcp

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/enrollment/registration/intake"
	"meshtransit.net/core/internal/domain/ipam"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const (
	testEnrollmentKey  = "mtc1.01890f90-0000-7000-8000-000000000001.AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA"
	testApprovalOrigin = "https://control.example.test"
)

// fakeStreams sends one snapshot per stream, then ends it with the error
// endFor returns for its node key, or blocks until the stream is cancelled.
type fakeStreams struct {
	snapshot mapsession.Snapshot
	endFor   func(node.Key) error

	mu       sync.Mutex
	requests []mapsession.Request
	reports  []mapsession.ClientEnforcement
	started  chan node.Key
}

func (streams *fakeStreams) Serve(ctx context.Context, _ control.AuthenticatedMachine, request mapsession.Request,
	sink mapsession.StreamSink) error {
	streams.mu.Lock()
	streams.requests = append(streams.requests, request)
	streams.mu.Unlock()
	if err := sink.SendSnapshot(ctx, streams.snapshot); err != nil {
		return err
	}
	streams.started <- request.NodeKey()
	if streams.endFor != nil {
		if err := streams.endFor(request.NodeKey()); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

func (streams *fakeStreams) ReportEnforcement(_ context.Context, _ control.AuthenticatedMachine,
	report mapsession.ClientEnforcement) error {
	streams.mu.Lock()
	defer streams.mu.Unlock()
	streams.reports = append(streams.reports, report)
	return nil
}

type fakeEndpoints struct {
	sets   []node.EndpointSet
	relays []int
}

func (endpoints *fakeEndpoints) ObserveSessionEndpoints(_ context.Context, _ mapsession.Snapshot, set node.EndpointSet,
	preferredRelay int, _ bool) error {
	endpoints.sets = append(endpoints.sets, set)
	endpoints.relays = append(endpoints.relays, preferredRelay)
	return nil
}

// fakeSnapshots knows which node keys are current.
type fakeSnapshots struct {
	mu       sync.Mutex
	current  map[node.Key]bool
	snapshot mapsession.Snapshot
}

func (snapshots *fakeSnapshots) Open(_ context.Context, _ control.AuthenticatedMachine,
	request mapsession.Request) (mapsession.Snapshot, error) {
	snapshots.mu.Lock()
	defer snapshots.mu.Unlock()
	if !snapshots.current[request.NodeKey()] {
		return mapsession.Snapshot{}, mapsession.ErrUnauthorized
	}
	return snapshots.snapshot, nil
}

type fakeRegistrations struct {
	mu       sync.Mutex
	result   registration.Result
	err      error
	requests []control.RegistrationRequest
}

func (registrations *fakeRegistrations) Register(_ context.Context, _ control.AuthenticatedMachine,
	request control.RegistrationRequest) (registration.Result, error) {
	registrations.mu.Lock()
	defer registrations.mu.Unlock()
	registrations.requests = append(registrations.requests, request)
	return registrations.result, registrations.err
}

func (registrations *fakeRegistrations) calls() []control.RegistrationRequest {
	registrations.mu.Lock()
	defer registrations.mu.Unlock()
	return append([]control.RegistrationRequest(nil), registrations.requests...)
}

type sequentialIDs struct{}

func (sequentialIDs) NewRegistrationID() (enrollment.RegistrationID, error) {
	return enrollment.ParseRegistrationID("01890f90-0000-7000-8000-0000000000aa")
}

// fakeBrowser issues one approval URL and completes it once approved.
type fakeBrowser struct {
	mu       sync.Mutex
	approved bool
	result   registration.Result
	issued   []string // follow-up URL of each issue call
}

func (browser *fakeBrowser) RegisterBrowser(_ context.Context, _ control.AuthenticatedMachine, _ node.Key,
	_ node.Hostname, followupURL string) (string, error) {
	browser.mu.Lock()
	defer browser.mu.Unlock()
	browser.issued = append(browser.issued, followupURL)
	if followupURL != "" && followupURL != testApprovalOrigin+approvalPath+"token-1" {
		return "", control.ErrInvalidBrowserRegistration
	}
	return testApprovalOrigin + approvalPath + "token-1", nil
}

func (browser *fakeBrowser) CompleteBrowser(_ context.Context, _ control.AuthenticatedMachine, _ node.Key,
	_ node.Hostname, followupURL string) (registration.Result, bool, error) {
	browser.mu.Lock()
	defer browser.mu.Unlock()
	if followupURL != testApprovalOrigin+approvalPath+"token-1" {
		return registration.Result{}, false, control.ErrInvalidBrowserRegistration
	}
	return browser.result, browser.approved, nil
}

func (browser *fakeBrowser) approve() {
	browser.mu.Lock()
	defer browser.mu.Unlock()
	browser.approved = true
}

type fakeLogout struct {
	mu   sync.Mutex
	err  error
	keys []node.Key
}

func (logout *fakeLogout) Logout(_ context.Context, _ control.AuthenticatedMachine, nodeKey node.Key) (
	control.DeviceLogout, error) {
	logout.mu.Lock()
	defer logout.mu.Unlock()
	logout.keys = append(logout.keys, nodeKey)
	return control.DeviceLogout{}, logout.err
}

type fakePaths struct {
	mu      sync.Mutex
	reports []distribution.PathReport
	nodes   []node.ID
}

func (paths *fakePaths) RecordPaths(_ context.Context, nodeID node.ID, _ int64, report distribution.PathReport) error {
	paths.mu.Lock()
	defer paths.mu.Unlock()
	paths.reports = append(paths.reports, report)
	paths.nodes = append(paths.nodes, nodeID)
	return nil
}

type fakeConnectivity struct {
	mu      sync.Mutex
	reports []distribution.Connectivity
}

func (c *fakeConnectivity) RecordConnectivity(_ context.Context, _ node.ID, _ int64, report distribution.Connectivity) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reports = append(c.reports, report)
	return nil
}

type conversationFixture struct {
	t             *testing.T
	session       *Session
	node          *nodeView
	control       key.ControlPrivate
	streams       *fakeStreams
	endpoints     *fakeEndpoints
	snapshots     *fakeSnapshots
	registrations *fakeRegistrations
	browser       *fakeBrowser
	logout        *fakeLogout
	paths         *fakePaths
	connectivity  *fakeConnectivity
	clockMu       sync.Mutex
	clock         time.Time
	talk          *conversation
}

func newConversationFixture(t *testing.T, openedBy sharedmtcp.MessageType) *conversationFixture {
	t.Helper()
	session, view, controlKey := testSession(t)
	session.openedBy = openedBy
	snapshot := streamFixture(t, 1)
	result := must(registration.NewResult(must(sequentialIDs{}.NewRegistrationID()), snapshot.Scope(),
		snapshot.NodeID(), snapshot.Hostname(), registration.DispositionCreated, 1))
	f := &conversationFixture{t: t, session: session, node: view, control: controlKey,
		streams:   &fakeStreams{snapshot: snapshot, started: make(chan node.Key, 8)},
		endpoints: &fakeEndpoints{}, snapshots: &fakeSnapshots{current: map[node.Key]bool{}, snapshot: snapshot},
		registrations: &fakeRegistrations{result: result}, browser: &fakeBrowser{result: result},
		logout: &fakeLogout{}, paths: &fakePaths{}, connectivity: &fakeConnectivity{},
		clock: time.Unix(1_800_000_000, 0)}
	application, err := NewApplication(ApplicationOptions{
		Streams: f.streams, Endpoints: f.endpoints, Snapshots: f.snapshots,
		ControlKeys: []ControlKey{{Private: controlKey, NotAfter: f.clock.Add(time.Hour)}},
		Logger:      slog.New(slog.DiscardHandler), Registrations: f.registrations, RegistrationIDs: sequentialIDs{},
		BrowserIssuer: f.browser, BrowserApproval: f.browser, Logout: f.logout, Paths: f.paths, Connectivity: f.connectivity,
		ApprovalOrigin: testApprovalOrigin,
		ApprovalTTL:    10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	application.now = f.now
	application.poll = 5 * time.Millisecond
	f.talk, _ = application.Open(session).(*conversation)
	return f
}

func (f *conversationFixture) now() time.Time {
	f.clockMu.Lock()
	defer f.clockMu.Unlock()
	return f.clock
}

func (f *conversationFixture) advance(d time.Duration) {
	f.clockMu.Lock()
	defer f.clockMu.Unlock()
	f.clock = f.clock.Add(d)
}

// run starts Run and stops it when the test ends.
func (f *conversationFixture) run() {
	ctx, cancel := context.WithCancel(f.t.Context())
	done := make(chan error, 1)
	go func() { done <- f.talk.Run(ctx) }()
	f.t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			f.t.Errorf("Run = %v", err)
		}
	})
}

// keys returns a node key and disco key with proofs for this session.
func (f *conversationFixture) keys(seed byte) (node.Key, []byte, []byte, []byte, []byte) {
	f.t.Helper()
	nodePrivate := must(key.NodePrivateFromBytes(repeat(seed, key.Size)))
	disco := must(key.NewDiscoPrivate())
	nodeProof := must(sharedmtcp.NodeKeyProof(nodePrivate, f.control.Public(), f.session.HandshakeHash()))
	discoProof := must(sharedmtcp.DiscoKeyProof(disco, f.control.Public(), f.session.HandshakeHash()))
	nodePublic, discoPublic := nodePrivate.Public(), disco.Public()
	return node.Key(nodePublic), nodePublic[:], nodeProof[:], discoPublic[:], discoProof[:]
}

func (f *conversationFixture) request(seed byte, auth *mtcpv1.RegisterRequest_Auth) *mtcpv1.RegisterRequest {
	_, nodeKey, nodeProof, discoKey, discoProof := f.keys(seed)
	return &mtcpv1.RegisterRequest{NodeKey: nodeKey, NodeKeyProof: nodeProof, DiscoKey: discoKey,
		DiscoKeyProof: discoProof, Hostinfo: &mtcpv1.Hostinfo{Hostname: "laptop"}, Auth: auth}
}

func enrollmentAuth(value string) *mtcpv1.RegisterRequest_Auth {
	return &mtcpv1.RegisterRequest_Auth{Method: &mtcpv1.RegisterRequest_Auth_EnrollmentKey{EnrollmentKey: value}}
}

func interactiveAuth(handle string) *mtcpv1.RegisterRequest_Auth {
	return &mtcpv1.RegisterRequest_Auth{Method: &mtcpv1.RegisterRequest_Auth_Interactive{
		Interactive: &mtcpv1.RegisterRequest_Interactive{ResumeHandle: handle}}}
}

func repeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// next waits for the next message Core sends.
func (f *conversationFixture) next() (sharedmtcp.MessageType, any) {
	f.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if t, m, ok := f.node.read(); ok {
			return t, m
		}
		select {
		case <-f.node.transport.signal:
		case <-time.After(10 * time.Millisecond):
		}
	}
	f.t.Fatal("no message from Core")
	return 0, nil
}

func (f *conversationFixture) expect(want sharedmtcp.MessageType) any {
	f.t.Helper()
	t, m := f.next()
	if t != want {
		f.t.Fatalf("got %#x %v, want %#x", uint8(t), m, uint8(want))
	}
	return m
}

func (f *conversationFixture) expectStream(nodeKey node.Key) {
	f.t.Helper()
	select {
	case got := <-f.streams.started:
		if got != nodeKey {
			f.t.Fatal("the stream serves another node key")
		}
	case <-time.After(5 * time.Second):
		f.t.Fatal("no map stream started")
	}
}

func TestLifecycleFor(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		err   error
		state mtcpv1.Lifecycle_State
		retry uint32
	}{
		{name: "suspended sent by the sink", err: mapsession.ErrSuspended},
		{name: "expired", err: mapsession.ErrAuthorizationExpired, state: mtcpv1.Lifecycle_EXPIRED},
		{name: "unauthorized is never revoked", err: mapsession.ErrUnauthorized, state: mtcpv1.Lifecycle_EXPIRED},
		{name: "presence conflict", err: mapsession.ErrPresenceConflict, state: mtcpv1.Lifecycle_RECONNECT, retry: 2000},
		{name: "other", err: errors.New("redis down"), state: mtcpv1.Lifecycle_RECONNECT, retry: 1000},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := lifecycleFor(test.err)
			if test.state == mtcpv1.Lifecycle_STATE_UNSPECIFIED {
				if got != nil {
					t.Fatalf("got %v, want none", got)
				}
				return
			}
			if got.GetState() != test.state || got.GetRetryAfterMs() != test.retry {
				t.Fatalf("got %v, want %v retry %d", got, test.state, test.retry)
			}
		})
	}
}

func TestUnauthorizedStreamKeepsTheSessionForRegistration(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	helloKey := node.Key(f.session.Hello().GetNodeKey())
	f.streams.endFor = func(nodeKey node.Key) error {
		if nodeKey == helloKey {
			return mapsession.ErrUnauthorized
		}
		return nil
	}
	f.run()
	f.expectStream(helloKey)
	f.expect(sharedmtcp.MessageKeyUpdate)
	f.expect(sharedmtcp.MessageMapSnapshot)
	if lifecycle := f.expect(sharedmtcp.MessageLifecycle).(*mtcpv1.Lifecycle); lifecycle.GetState() !=
		mtcpv1.Lifecycle_EXPIRED {
		t.Fatalf("lifecycle %v", lifecycle)
	}
	// The same session registers and gets its map.
	registered, _, _, _, _ := f.keys(3)
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest,
		f.request(3, enrollmentAuth(testEnrollmentKey))); err != nil {
		t.Fatal(err)
	}
	f.expectStream(registered)
	authorized := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetAuthorized()
	if authorized.GetDeviceId() != f.streams.snapshot.NodeID().String() || len(authorized.GetAddresses()) == 0 {
		t.Fatalf("authorized %v", authorized)
	}
	f.expect(sharedmtcp.MessageMapSnapshot)
}

func TestRegistrationWithEnrollmentKey(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name     string
		mutate   func(f *conversationFixture, request *mtcpv1.RegisterRequest)
		err      error
		want     mtcpv1.RegisterResponse_Rejected_Code
		reported bool // the domain saw the request
	}{
		{name: "authorized", reported: true},
		{name: "wrong node key proof", mutate: func(_ *conversationFixture, request *mtcpv1.RegisterRequest) {
			request.NodeKeyProof[0] ^= 1
		}, want: mtcpv1.RegisterResponse_Rejected_INVALID},
		{name: "proof from another session", mutate: func(f *conversationFixture, request *mtcpv1.RegisterRequest) {
			other := newConversationFixture(f.t, sharedmtcp.MessageRegisterRequest)
			_, _, _, discoKey, discoProof := other.keys(5)
			request.DiscoKey, request.DiscoKeyProof = discoKey, discoProof
		}, want: mtcpv1.RegisterResponse_Rejected_INVALID},
		{name: "node key equals disco key", mutate: func(_ *conversationFixture, request *mtcpv1.RegisterRequest) {
			request.DiscoKey, request.DiscoKeyProof = request.NodeKey, request.NodeKeyProof
		}, want: mtcpv1.RegisterResponse_Rejected_INVALID},
		{name: "bad hostname", mutate: func(_ *conversationFixture, request *mtcpv1.RegisterRequest) {
			request.Hostinfo.Hostname = "bad host/name"
		}, want: mtcpv1.RegisterResponse_Rejected_INVALID},
		{name: "malformed key", mutate: func(_ *conversationFixture, request *mtcpv1.RegisterRequest) {
			request.Auth = enrollmentAuth("mtc1.nope")
		}, want: mtcpv1.RegisterResponse_Rejected_CREDENTIAL_INVALID},
		{name: "wrong secret", err: intake.ErrAuthenticationFailed, reported: true,
			want: mtcpv1.RegisterResponse_Rejected_CREDENTIAL_INVALID},
		{name: "key conflict", err: registration.ErrIntentConflict, reported: true,
			want: mtcpv1.RegisterResponse_Rejected_CONFLICT},
		// A full Network is permanent until an admin adds a range: the node
		// must not retry every two seconds.
		{name: "no free address", err: errors.Join(errors.New("allocation"), ipam.ErrAddressExhausted),
			reported: true, want: mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED},
		{name: "renewal without approval", mutate: func(_ *conversationFixture, request *mtcpv1.RegisterRequest) {
			request.Auth = &mtcpv1.RegisterRequest_Auth{Method: &mtcpv1.RegisterRequest_Auth_Resume{
				Resume: &mtcpv1.RegisterRequest_Resume{}}}
		}, want: mtcpv1.RegisterResponse_Rejected_EXPIRED},
		{name: "no method", mutate: func(_ *conversationFixture, request *mtcpv1.RegisterRequest) {
			request.Auth = nil
		}, want: mtcpv1.RegisterResponse_Rejected_INVALID},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
			f.registrations.err = test.err
			f.run()
			request := f.request(9, enrollmentAuth(testEnrollmentKey))
			if test.mutate != nil {
				test.mutate(f, request)
			}
			if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, request); err != nil {
				t.Fatal(err)
			}
			if got := len(f.registrations.calls()) == 1; got != test.reported {
				t.Fatalf("domain saw the request: %t, want %t", got, test.reported)
			}
			response := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse)
			if test.want != mtcpv1.RegisterResponse_Rejected_CODE_UNSPECIFIED {
				if response.GetRejected().GetCode() != test.want {
					t.Fatalf("response %v, want rejected %v", response, test.want)
				}
				return
			}
			call := f.registrations.calls()[0]
			if !call.IsCredentialRegistration() || response.GetAuthorized() == nil {
				t.Fatalf("response %v", response)
			}
			f.expectStream(node.Key(request.GetNodeKey()))
			f.expect(sharedmtcp.MessageKeyUpdate)
			f.expect(sharedmtcp.MessageMapSnapshot)
		})
	}
}

func TestInteractiveRegistrationWaitsForApproval(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.run()
	request := f.request(4, interactiveAuth(""))
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, request); err != nil {
		t.Fatal(err)
	}
	pending := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetPending()
	if pending.GetApprovalUrl() != testApprovalOrigin+approvalPath+"token-1" || pending.GetResumeHandle() != "token-1" ||
		pending.GetExpiresMs() != f.now().Add(10*time.Minute).UnixMilli() {
		t.Fatalf("pending %v", pending)
	}
	// Nothing happens until the approval; then Core answers on its own.
	select {
	case <-f.streams.started:
		t.Fatal("a stream started before the approval")
	case <-time.After(30 * time.Millisecond):
	}
	f.browser.approve()
	f.expectStream(node.Key(request.GetNodeKey()))
	if f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetAuthorized() == nil {
		t.Fatal("no authorized response after the approval")
	}
}

func TestInteractiveRegistrationExpires(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.run()
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, f.request(4, interactiveAuth(""))); err != nil {
		t.Fatal(err)
	}
	f.expect(sharedmtcp.MessageRegisterResponse)
	f.advance(10 * time.Minute)
	if got := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetRejected().GetCode(); got !=
		mtcpv1.RegisterResponse_Rejected_EXPIRED {
		t.Fatalf("expiry answered %v", got)
	}
}

func TestInteractiveRegistrationResumesAfterReconnect(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.run()
	f.browser.approve()
	request := f.request(4, interactiveAuth("token-1"))
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, request); err != nil {
		t.Fatal(err)
	}
	if f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetAuthorized() == nil {
		t.Fatal("an approved resume handle did not authorize")
	}
	f.expectStream(node.Key(request.GetNodeKey()))
	// Handles never move between approvals.
	other := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	other.run()
	for _, handle := range []string{"token-2", "../token-1", "token-1/x"} {
		if err := other.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest,
			other.request(4, interactiveAuth(handle))); err != nil {
			t.Fatal(err)
		}
		code := other.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetRejected().GetCode()
		if code != mtcpv1.RegisterResponse_Rejected_EXPIRED && code != mtcpv1.RegisterResponse_Rejected_INVALID {
			t.Fatalf("handle %q answered %v", handle, code)
		}
	}
}

func TestRotateNodeKey(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	helloKey := node.Key(f.session.Hello().GetNodeKey())
	f.run()
	f.expectStream(helloKey)
	f.expect(sharedmtcp.MessageKeyUpdate)
	f.expect(sharedmtcp.MessageMapSnapshot)
	newKey, nodeKey, nodeProof, discoKey, discoProof := f.keys(6)
	rotate := &mtcpv1.RotateNodeKey{NewNodeKey: nodeKey, NodeKeyProof: nodeProof, NewDiscoKey: discoKey,
		DiscoKeyProof: discoProof}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRotateNodeKey, rotate); err != nil {
		t.Fatal(err)
	}
	response := f.expect(sharedmtcp.MessageRotateNodeKeyResponse).(*mtcpv1.RotateNodeKeyResponse)
	calls := f.registrations.calls()
	if string(response.GetNodeKey()) != string(nodeKey) || len(calls) != 1 || !calls[0].IsNodeKeyRotation() {
		t.Fatalf("rotation response %v, calls %d", response, len(calls))
	}
	f.expectStream(newKey)
	// A repeat after a crash: the new key is already current, so Core
	// answers without rotating again.
	f.snapshots.current[newKey] = true
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRotateNodeKey, rotate); err != nil {
		t.Fatal(err)
	}
	for {
		if t2, _ := f.next(); t2 == sharedmtcp.MessageRotateNodeKeyResponse {
			break
		}
	}
	if len(f.registrations.calls()) != 1 {
		t.Fatal("a repeated rotation reached the domain again")
	}
	// Proofs bind to the session.
	rotate.NodeKeyProof = append([]byte(nil), rotate.NodeKeyProof...)
	rotate.NodeKeyProof[3] ^= 1
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRotateNodeKey, rotate); err != nil {
		t.Fatal(err)
	}
	for {
		if t2, m := f.next(); t2 == sharedmtcp.MessageError {
			if m.(*mtcpv1.Error).GetCode() != mtcpv1.Error_INVALID || m.(*mtcpv1.Error).GetFatal() {
				t.Fatalf("bad proof answered %v", m)
			}
			break
		}
	}
}

func TestRotationNeedsAnAuthorizedDevice(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.run()
	_, nodeKey, nodeProof, discoKey, discoProof := f.keys(6)
	f.session.hello.NodeKey = nil
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRotateNodeKey, &mtcpv1.RotateNodeKey{NewNodeKey: nodeKey,
		NodeKeyProof: nodeProof, NewDiscoKey: discoKey, DiscoKeyProof: discoProof}); err != nil {
		t.Fatal(err)
	}
	if m := f.expect(sharedmtcp.MessageError).(*mtcpv1.Error); m.GetCode() != mtcpv1.Error_NOT_AUTHORIZED {
		t.Fatalf("rotation without a Device answered %v", m)
	}
}

func TestConversationEndpointReports(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	report := func(endpoints ...*mtcpv1.Endpoint) *mtcpv1.EndpointReport {
		disco := make([]byte, 32)
		disco[0] = 9
		return &mtcpv1.EndpointReport{DiscoKey: disco, Endpoints: endpoints, PreferredRelay: 3}
	}
	public := &mtcpv1.Endpoint{Ip: []byte{198, 51, 100, 7}, Port: 41641, Kind: mtcpv1.Endpoint_SERVER_REFLEXIVE}
	// Before the first map a report has nothing to bind to.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, report(public)); err != nil ||
		len(f.endpoints.sets) != 0 {
		t.Fatalf("report before a map: %v, %d stored", err, len(f.endpoints.sets))
	}
	if err := f.talk.sink.SendSnapshot(t.Context(), streamFixture(t, 1)); err != nil {
		t.Fatal(err)
	}
	loopback := &mtcpv1.Endpoint{Ip: []byte{127, 0, 0, 1}, Port: 41641, Kind: mtcpv1.Endpoint_HOST}
	unknown := &mtcpv1.Endpoint{Ip: []byte{198, 51, 100, 8}, Port: 1, Kind: mtcpv1.Endpoint_Kind(99)}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, report(public, loopback, unknown)); err != nil {
		t.Fatal(err)
	}
	if len(f.endpoints.sets) != 1 || len(f.endpoints.sets[0].Endpoints()) != 1 || f.endpoints.relays[0] != 3 {
		t.Fatalf("stored %v, want only the public endpoint and relay 3", f.endpoints.sets)
	}
	// A second report within a second is dropped; after it, accepted.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, report(public)); err != nil ||
		len(f.endpoints.sets) != 1 {
		t.Fatalf("fast report: %v, %d stored", err, len(f.endpoints.sets))
	}
	f.advance(endpointReportInterval)
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, report()); err != nil ||
		len(f.endpoints.sets) != 2 {
		t.Fatalf("report after the interval: %v, %d stored", err, len(f.endpoints.sets))
	}
	for name, bad := range map[string]*mtcpv1.EndpointReport{
		"short disco key": {DiscoKey: []byte{1}},
		"zero disco key":  {DiscoKey: make([]byte, 32)},
		"bad address":     report(&mtcpv1.Endpoint{Ip: []byte{1, 2, 3}, Port: 1, Kind: mtcpv1.Endpoint_HOST}),
		"bad port":        report(&mtcpv1.Endpoint{Ip: []byte{198, 51, 100, 7}, Port: 70000, Kind: mtcpv1.Endpoint_HOST}),
		"too many":        report(make([]*mtcpv1.Endpoint, maxReportedEndpoints+1)...),
	} {
		f.advance(endpointReportInterval)
		var violation protocolError
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, bad); !errors.As(err, &violation) {
			t.Errorf("%s: %v, want a violation", name, err)
		}
	}
}

func TestConversationEnforcementAndUnexpectedMessages(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	f.talk.nodeKey = node.Key(f.session.Hello().GetNodeKey())
	digest := make([]byte, 32)
	digest[0] = 1
	report := &mtcpv1.EnforcementReport{Digest: digest, Grants: 4, AppliedMs: f.now().UnixMilli()}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEnforcementReport, report); err != nil {
		t.Fatal(err)
	}
	if len(f.streams.reports) != 1 || f.streams.reports[0].Filter.Grants() != 4 ||
		!f.streams.reports[0].AppliedAt.Equal(time.UnixMilli(f.now().UnixMilli())) {
		t.Fatalf("enforcement reports %v", f.streams.reports)
	}
	// Malformed evidence is ignored, never stored.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEnforcementReport,
		&mtcpv1.EnforcementReport{Digest: []byte{1}, AppliedMs: 1}); err != nil || len(f.streams.reports) != 1 {
		t.Fatalf("malformed report: %v, %d stored", err, len(f.streams.reports))
	}
	var violation protocolError
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageMapSnapshot, &mtcpv1.MapSnapshot{}); !errors.As(err, &violation) {
		t.Fatalf("a Core-only message from a node: %v", err)
	}
}

func TestLogout(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	helloKey := node.Key(f.session.Hello().GetNodeKey())
	f.run()
	f.expectStream(helloKey)
	f.expect(sharedmtcp.MessageKeyUpdate)
	f.expect(sharedmtcp.MessageMapSnapshot)
	// A failed logout changes nothing: the stream resumes.
	f.logout.err = control.ErrDeviceLogoutNotFound
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageLogout, &mtcpv1.Logout{}); err != nil {
		t.Fatal(err)
	}
	if m := f.expect(sharedmtcp.MessageError).(*mtcpv1.Error); m.GetCode() != mtcpv1.Error_NOT_AUTHORIZED {
		t.Fatalf("failed logout answered %v", m)
	}
	f.expectStream(helloKey)
	f.expect(sharedmtcp.MessageMapSnapshot)
	f.logout.err = nil
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageLogout, &mtcpv1.Logout{}); !errors.Is(err, errLoggedOut) {
		t.Fatalf("logout returned %v; the session must end", err)
	}
	if m := f.expect(sharedmtcp.MessageLifecycle).(*mtcpv1.Lifecycle); m.GetState() != mtcpv1.Lifecycle_LOGGED_OUT {
		t.Fatalf("logout sent %v", m)
	}
	if len(f.logout.keys) != 2 || f.logout.keys[1] != helloKey {
		t.Fatal("logout did not name the session's node key")
	}
}

func TestLogoutNeedsAnAuthorizedDevice(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.run()
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageLogout, &mtcpv1.Logout{}); err != nil {
		t.Fatal(err)
	}
	if m := f.expect(sharedmtcp.MessageError).(*mtcpv1.Error); m.GetCode() != mtcpv1.Error_NOT_AUTHORIZED {
		t.Fatalf("logout without a Device answered %v", m)
	}
	if len(f.logout.keys) != 0 {
		t.Fatal("logout reached the domain without a Device")
	}
}

func TestEndpointReportsUseTheProvenDiscoKey(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.run()
	request := f.request(8, enrollmentAuth(testEnrollmentKey))
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, request); err != nil {
		t.Fatal(err)
	}
	f.expectStream(node.Key(request.GetNodeKey()))
	f.expect(sharedmtcp.MessageRegisterResponse)
	f.expect(sharedmtcp.MessageKeyUpdate)
	f.expect(sharedmtcp.MessageMapSnapshot)
	other := append([]byte(nil), request.GetDiscoKey()...)
	other[0] ^= 1
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport,
		&mtcpv1.EndpointReport{DiscoKey: other}); err != nil {
		t.Fatal(err)
	}
	if m := f.expect(sharedmtcp.MessageError).(*mtcpv1.Error); m.GetCode() != mtcpv1.Error_INVALID || m.GetFatal() ||
		len(f.endpoints.sets) != 0 {
		t.Fatalf("another disco key: %v, %d stored", m, len(f.endpoints.sets))
	}
	// A node without candidates still reports, so its relay grant follows.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport,
		&mtcpv1.EndpointReport{DiscoKey: request.GetDiscoKey()}); err != nil {
		t.Fatal(err)
	}
	if len(f.endpoints.sets) != 1 || len(f.endpoints.sets[0].Endpoints()) != 0 {
		t.Fatalf("empty report with the proven disco key: %d stored", len(f.endpoints.sets))
	}
}

// A node that reconnects only to rotate sends RotateNodeKey before its map
// arrives: the current key's snapshot names the Device.
func TestRotateNodeKeyBeforeTheFirstMap(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	helloKey := node.Key(f.session.Hello().GetNodeKey())
	f.snapshots.current[helloKey] = true
	_, nodeKey, nodeProof, discoKey, discoProof := f.keys(6)
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRotateNodeKey, &mtcpv1.RotateNodeKey{NewNodeKey: nodeKey,
		NodeKeyProof: nodeProof, NewDiscoKey: discoKey, DiscoKeyProof: discoProof}); err != nil {
		t.Fatal(err)
	}
	if response := f.expect(sharedmtcp.MessageRotateNodeKeyResponse).(*mtcpv1.RotateNodeKeyResponse); string(response.GetNodeKey()) != string(nodeKey) {
		t.Fatal("rotation answered another key")
	}
	if calls := f.registrations.calls(); len(calls) != 1 || !calls[0].IsNodeKeyRotation() {
		t.Fatalf("rotation reached the domain %d times", len(calls))
	}
}

func TestPathStatsAreStoredForMapPeers(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	// Before a map there is nothing to bind the report to.
	report := &mtcpv1.PathStatsReport{IntervalS: 60, Peers: []*mtcpv1.PeerPathStats{{DeviceId: "x"}}}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessagePathStatsReport, report); err != nil || len(f.paths.reports) != 0 {
		t.Fatalf("report before a map: %v", err)
	}
	snapshot := streamFixture(t, 2)
	if err := f.talk.sink.SendSnapshot(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	peers := snapshot.AuthorizedPeers()
	if len(peers) == 0 {
		t.Fatal("fixture has no peers")
	}
	known := peers[0].NodeID().String()
	report = &mtcpv1.PathStatsReport{IntervalS: 60, Peers: []*mtcpv1.PeerPathStats{
		{DeviceId: known, Technique: mtcpv1.PeerPathStats_RELAY, RelayRegion: 1,
			RelayReason: mtcpv1.PeerPathStats_NO_RESPONSE, RelayTxBytes: 10, RelayRxBytes: 20},
		{DeviceId: "01890f00-0000-7000-8000-000000000999", Technique: mtcpv1.PeerPathStats_DIRECT},
	}}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessagePathStatsReport, report); err != nil {
		t.Fatal(err)
	}
	if len(f.paths.reports) != 1 || f.paths.nodes[0] != snapshot.NodeID() {
		t.Fatalf("stored %d reports", len(f.paths.reports))
	}
	stored := f.paths.reports[0]
	if stored.Interval != time.Minute || len(stored.Peers) != 1 || stored.Peers[0].Kind != distribution.PathRelay ||
		stored.Peers[0].RelayCode != "sin" || stored.Peers[0].RelayReason != distribution.RelayNoResponse ||
		stored.Peers[0].RelayBytes != 30 {
		t.Fatalf("stored %+v", stored)
	}
	// Reports closer than the interval are dropped; afterwards stored.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessagePathStatsReport, report); err != nil || len(f.paths.reports) != 1 {
		t.Fatalf("fast report: %v, %d stored", err, len(f.paths.reports))
	}
	f.advance(pathReportInterval)
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessagePathStatsReport, report); err != nil || len(f.paths.reports) != 2 {
		t.Fatalf("report after the interval: %v, %d stored", err, len(f.paths.reports))
	}
	var violation protocolError
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessagePathStatsReport,
		&mtcpv1.PathStatsReport{IntervalS: 0}); !errors.As(err, &violation) {
		t.Fatalf("an empty interval: %v", err)
	}
}

func TestConversationStoresConnectivityWhenItChanges(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	if err := f.talk.sink.SendSnapshot(t.Context(), streamFixture(t, 1)); err != nil {
		t.Fatal(err)
	}
	disco := make([]byte, 32)
	disco[0] = 9
	observed := f.now().Add(-time.Minute)
	report := &mtcpv1.EndpointReport{DiscoKey: disco, Ipv6Global: true,
		Nat:           &mtcpv1.NatInfo{Mapping: 4, Filtering: 3, Allocation: 2, SequentialStep: 2},
		NatObservedMs: observed.UnixMilli(),
		PortMapping:   &mtcpv1.PortMapping{Protocol: 3, State: 3, ExpiresMs: f.now().Add(time.Hour).UnixMilli()}}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, report); err != nil {
		t.Fatal(err)
	}
	if len(f.connectivity.reports) != 1 {
		t.Fatalf("stored %d connectivity reports", len(f.connectivity.reports))
	}
	stored := f.connectivity.reports[0]
	if stored.NAT == nil || stored.NAT.Mapping != distribution.NATMappingAddressAndPortDependent ||
		stored.NAT.Allocation != distribution.NATAllocationSequential || stored.NAT.SequentialStep != 2 ||
		!stored.NAT.ObservedAt.Equal(observed) || !stored.IPv6Global || stored.IPv6STUN ||
		stored.PortMapping == nil || stored.PortMapping.Protocol != distribution.PortMappingProtocolUPnP ||
		stored.PortMapping.State != distribution.PortMappingMapped || !stored.IsValid() {
		t.Fatalf("stored %+v", stored)
	}
	// The same connectivity again is not stored again.
	f.advance(endpointReportInterval)
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, report); err != nil || len(f.connectivity.reports) != 1 {
		t.Fatalf("unchanged report: %v, %d stored", err, len(f.connectivity.reports))
	}
	// A change is; codes a newer node sends read as unknown.
	f.advance(endpointReportInterval)
	report.Nat = &mtcpv1.NatInfo{Mapping: 9, Filtering: 1, Allocation: 1}
	report.PortMapping = &mtcpv1.PortMapping{Protocol: 7, State: 42}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, report); err != nil || len(f.connectivity.reports) != 2 {
		t.Fatalf("changed report: %v, %d stored", err, len(f.connectivity.reports))
	}
	changed := f.connectivity.reports[1]
	if changed.NAT.Mapping != distribution.NATMappingUnknown || changed.PortMapping.Protocol != distribution.PortMappingProtocolUnknown ||
		changed.PortMapping.State != distribution.PortMappingUnknown || !changed.IsValid() {
		t.Fatalf("changed %+v", changed)
	}
}

// TestServeDeclaresLargeMapsOnlyForClientsThatDo: the map stream's request
// carries map.large1 exactly when the session negotiated it, so a client
// without it keeps the 256-peer bound it can apply.
func TestServeDeclaresLargeMapsOnlyForClientsThatDo(t *testing.T) {
	t.Parallel()
	for _, large := range []bool{false, true} {
		f := newConversationFixture(t, sharedmtcp.MessagePing)
		if large {
			f.session.capabilities = append(f.session.capabilities, "map.large1")
		}
		nodeKey := f.streams.snapshot.NodeKey()
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() { done <- f.talk.serve(ctx, nodeKey) }()
		f.expectStream(nodeKey)
		cancel()
		<-done
		f.streams.mu.Lock()
		requests := append([]mapsession.Request(nil), f.streams.requests...)
		f.streams.mu.Unlock()
		if len(requests) != 1 || requests[0].LargeMap() != large {
			t.Fatalf("map.large1 negotiated %v: requests %d, large %v", large, len(requests), len(requests) == 1 && requests[0].LargeMap())
		}
	}
}

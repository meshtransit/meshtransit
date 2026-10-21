package mtcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/enrollment/registration/intake"
	"meshtransit.net/core/internal/domain/ipam"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/node/keyrotation"
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

	mu        sync.Mutex
	requests  []mapsession.Request
	reports   []mapsession.ClientEnforcement
	health    [][]mapsession.SiteHealth
	exits     []*mapsession.ExitHealth
	selection [][]mapsession.SiteSelection
	// exitSelections are the exit selections stored, one per report.
	exitSelections []*mapsession.ExitSelection
	started        chan node.Key
	// block, when set, holds the next ReportEnforcement until it is closed;
	// entered is signalled when that call starts.
	block   chan struct{}
	entered chan struct{}
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

func (streams *fakeStreams) ReportRouteSelection(_ context.Context, _ control.AuthenticatedMachine, _ node.Key,
	sites []mapsession.SiteSelection, exit *mapsession.ExitSelection,
) error {
	streams.mu.Lock()
	defer streams.mu.Unlock()
	streams.selection = append(streams.selection, slices.Clone(sites))
	streams.exitSelections = append(streams.exitSelections, exit)
	return nil
}

func (streams *fakeStreams) ReportRouteHealth(_ context.Context, _ control.AuthenticatedMachine, _ node.Key,
	sites []mapsession.SiteHealth, exit *mapsession.ExitHealth) error {
	streams.mu.Lock()
	defer streams.mu.Unlock()
	streams.health = append(streams.health, slices.Clone(sites))
	streams.exits = append(streams.exits, exit)
	return nil
}

func (streams *fakeStreams) ReportEnforcement(_ context.Context, _ control.AuthenticatedMachine,
	report mapsession.ClientEnforcement) error {
	streams.mu.Lock()
	block, entered := streams.block, streams.entered
	streams.block, streams.entered = nil, nil
	streams.mu.Unlock()
	if block != nil {
		close(entered)
		<-block
	}
	streams.mu.Lock()
	defer streams.mu.Unlock()
	streams.reports = append(streams.reports, report)
	return nil
}

type fakeEndpoints struct {
	mu     sync.Mutex
	sets   []node.EndpointSet
	relays []int
	// announcement is what each observation answers; flushes counts
	// FlushSessionEndpoints calls, each answering the next of flushResults.
	announcement mapsession.EndpointAnnouncement
	flushes      int
	flushResults []mapsession.EndpointAnnouncement
	// observeErrs and flushErrs fail the next calls, one error each.
	observeErrs []error
	flushErrs   []error
	attempts    int
	// block, when set, holds the next observation until it is closed;
	// entered is signalled when that observation starts.
	block   chan struct{}
	entered chan struct{}
}

func (endpoints *fakeEndpoints) ObserveSessionEndpoints(_ context.Context, _ mapsession.Snapshot, set node.EndpointSet,
	preferredRelay int, _ bool) (mapsession.EndpointAnnouncement, error) {
	endpoints.mu.Lock()
	block, entered := endpoints.block, endpoints.entered
	endpoints.block, endpoints.entered = nil, nil
	endpoints.mu.Unlock()
	if block != nil {
		close(entered)
		<-block
	}
	endpoints.mu.Lock()
	defer endpoints.mu.Unlock()
	endpoints.attempts++
	if len(endpoints.observeErrs) > 0 {
		err := endpoints.observeErrs[0]
		endpoints.observeErrs = endpoints.observeErrs[1:]
		return mapsession.EndpointAnnouncement{}, err
	}
	endpoints.sets = append(endpoints.sets, set)
	endpoints.relays = append(endpoints.relays, preferredRelay)
	return endpoints.announcement, nil
}

func (endpoints *fakeEndpoints) FlushSessionEndpoints(context.Context, mapsession.Snapshot) (
	mapsession.EndpointAnnouncement, error) {
	endpoints.mu.Lock()
	defer endpoints.mu.Unlock()
	endpoints.flushes++
	if len(endpoints.flushErrs) > 0 {
		err := endpoints.flushErrs[0]
		endpoints.flushErrs = endpoints.flushErrs[1:]
		return mapsession.EndpointAnnouncement{}, err
	}
	if len(endpoints.flushResults) == 0 {
		return mapsession.EndpointAnnouncement{}, nil
	}
	result := endpoints.flushResults[0]
	endpoints.flushResults = endpoints.flushResults[1:]
	return result, nil
}

func (endpoints *fakeEndpoints) stored() int {
	endpoints.mu.Lock()
	defer endpoints.mu.Unlock()
	return len(endpoints.sets)
}

// fakeTimer is the conversation's endpoint timer; the test fires it.
type fakeTimer struct {
	mu    sync.Mutex
	fire  func()
	delay time.Duration
	armed bool
}

func (timer *fakeTimer) start(delay time.Duration, fire func()) endpointTimer {
	timer.mu.Lock()
	defer timer.mu.Unlock()
	timer.fire, timer.delay, timer.armed = fire, delay, true
	return timer
}

func (timer *fakeTimer) Reset(delay time.Duration) bool {
	timer.mu.Lock()
	defer timer.mu.Unlock()
	timer.delay, timer.armed = delay, true
	return true
}

func (timer *fakeTimer) Stop() bool {
	timer.mu.Lock()
	defer timer.mu.Unlock()
	armed := timer.armed
	timer.armed = false
	return armed
}

// pending reports whether the timer is armed and for how long.
func (timer *fakeTimer) pending() (time.Duration, bool) {
	timer.mu.Lock()
	defer timer.mu.Unlock()
	return timer.delay, timer.armed
}

// trigger runs the timer's function as if it had expired.
func (timer *fakeTimer) trigger() {
	timer.mu.Lock()
	fire := timer.fire
	timer.armed = false
	timer.mu.Unlock()
	fire()
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
	err      error    // what completing an approval fails with, if set
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
	if browser.err != nil {
		return registration.Result{}, false, browser.err
	}
	return browser.result, browser.approved, nil
}

func (browser *fakeBrowser) fail(err error) {
	browser.mu.Lock()
	defer browser.mu.Unlock()
	browser.err = err
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
	timer         *fakeTimer
	// enforcementTimer is the enforcement pacing's timer.
	enforcementTimer *fakeTimer
	// routeOfferTimer is the route offer pacing's timer.
	routeOfferTimer *fakeTimer
	// routeHealthTimer is the route health pacing's timer.
	routeHealthTimer *fakeTimer
	routeOffers      *fakeRouteOffers
}

func newConversationFixture(t *testing.T, openedBy sharedmtcp.MessageType) *conversationFixture {
	t.Helper()
	session, view, controlKey := testSession(t)
	session.openedBy = openedBy
	// Session.run sets it before any message; endpoint pacing works under it.
	session.ctx, session.cancel = context.WithCancelCause(t.Context())
	snapshot := streamFixture(t, 1)
	result := must(registration.NewResult(must(sequentialIDs{}.NewRegistrationID()), snapshot.Scope(),
		snapshot.NodeID(), snapshot.Hostname(), registration.DispositionCreated, 1))
	f := &conversationFixture{t: t, session: session, node: view, control: controlKey,
		streams:   &fakeStreams{snapshot: snapshot, started: make(chan node.Key, 8)},
		endpoints: &fakeEndpoints{}, snapshots: &fakeSnapshots{current: map[node.Key]bool{}, snapshot: snapshot},
		registrations: &fakeRegistrations{result: result}, browser: &fakeBrowser{result: result},
		logout: &fakeLogout{}, paths: &fakePaths{}, connectivity: &fakeConnectivity{},
		routeOffers: &fakeRouteOffers{}, clock: time.Unix(1_800_000_000, 0)}
	application, err := NewApplication(ApplicationOptions{
		Streams: f.streams, Endpoints: f.endpoints, Snapshots: f.snapshots,
		ControlKeys: []ControlKey{{Private: controlKey, NotAfter: f.clock.Add(time.Hour)}},
		Logger:      slog.New(slog.DiscardHandler), Registrations: f.registrations, RegistrationIDs: sequentialIDs{},
		BrowserIssuer: f.browser, BrowserApproval: f.browser, Logout: f.logout, Paths: f.paths, Connectivity: f.connectivity,
		RouteOffers:    f.routeOffers,
		ApprovalOrigin: testApprovalOrigin,
		ApprovalTTL:    10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	application.now = f.now
	application.poll = 5 * time.Millisecond
	f.timer = &fakeTimer{}
	application.endpointTimer = f.timer.start
	f.enforcementTimer = &fakeTimer{}
	application.enforcementTimer = f.enforcementTimer.start
	f.routeOfferTimer = &fakeTimer{}
	application.routeOfferTimer = f.routeOfferTimer.start
	f.routeHealthTimer = &fakeTimer{}
	application.routeHealthTimer = f.routeHealthTimer.start
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
		{name: "a proven revocation is revoked", err: errors.Join(mapsession.ErrStreamUnavailable, mapsession.ErrRevoked),
			state: mtcpv1.Lifecycle_REVOKED},
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

// A revoked Device's keys never come back: registering on the same session
// cannot repair it, and the metric names the cause.
func TestRevokedStreamIsNotRepairedByRegistration(t *testing.T) {
	t.Parallel()
	if needsRegistration(mapsession.ErrRevoked) {
		t.Fatal("a revoked Device must not be asked to register on the same session")
	}
	if !needsRegistration(mapsession.ErrUnauthorized) || !needsRegistration(mapsession.ErrAuthorizationExpired) {
		t.Fatal("an unauthorized or expired Device may still register on the same session")
	}
	if got := streamEndReason(mapsession.ErrRevoked); got != "revoked" {
		t.Fatalf("streamEndReason(ErrRevoked) = %q, want revoked", got)
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

func TestInteractiveRegistrationAnswersLastingRefusals(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		err     error
		message string
	}{
		{errors.Join(control.ErrBrowserRegistrationUnavailable, registration.ErrNewDeviceLimit), newDeviceLimit.message},
		{errors.Join(control.ErrBrowserRegistrationUnavailable, ipam.ErrAddressExhausted), networkFull.message},
	} {
		// While the approval is awaited: answered once, not retried each tick.
		f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
		f.run()
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, f.request(4, interactiveAuth(""))); err != nil {
			t.Fatal(err)
		}
		f.expect(sharedmtcp.MessageRegisterResponse)
		f.browser.fail(test.err)
		rejected := f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetRejected()
		if rejected.GetCode() != mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED || rejected.GetMessage() != test.message {
			t.Fatalf("awaited approval answered %v", rejected)
		}
		// On a resume after a reconnect.
		resumed := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
		resumed.run()
		resumed.browser.fail(test.err)
		if err := resumed.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest,
			resumed.request(4, interactiveAuth("token-1"))); err != nil {
			t.Fatal(err)
		}
		rejected = resumed.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetRejected()
		if rejected.GetCode() != mtcpv1.RegisterResponse_Rejected_NOT_PERMITTED || rejected.GetMessage() != test.message {
			t.Fatalf("resumed approval answered %v", rejected)
		}
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

func TestRotationOverTheDeviceBudgetIsRefused(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	f.run()
	f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
	f.expect(sharedmtcp.MessageKeyUpdate)
	f.expect(sharedmtcp.MessageMapSnapshot)
	f.registrations.mu.Lock()
	f.registrations.err = fmt.Errorf("%w: rotate authenticated Node key: %w", control.ErrRegistrationFailed,
		&keyrotation.RateLimitedError{RetryAfter: 40 * time.Minute})
	f.registrations.mu.Unlock()
	_, nodeKey, nodeProof, discoKey, discoProof := f.keys(6)
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRotateNodeKey, &mtcpv1.RotateNodeKey{NewNodeKey: nodeKey,
		NodeKeyProof: nodeProof, NewDiscoKey: discoKey, DiscoKeyProof: discoProof}); err != nil {
		t.Fatal(err)
	}
	m := f.expect(sharedmtcp.MessageError).(*mtcpv1.Error)
	if m.GetCode() != mtcpv1.Error_NOT_PERMITTED || m.GetRetryAfterMs() != 2_400_000 || m.GetFatal() {
		t.Fatalf("rotation over the budget answered %v", m)
	}
}

func TestIdentityRequestsOverTheSessionBudgetAreOverloaded(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	f.run()
	f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
	f.expect(sharedmtcp.MessageKeyUpdate)
	f.expect(sharedmtcp.MessageMapSnapshot)
	f.talk.identity.spent = identityBurst // a session that already sent its burst
	f.talk.identity.updated = f.talk.application.now()
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRotateNodeKey, &mtcpv1.RotateNodeKey{}); err != nil {
		t.Fatal(err)
	}
	if m := f.expect(sharedmtcp.MessageError).(*mtcpv1.Error); m.GetCode() != mtcpv1.Error_OVERLOADED ||
		m.GetRetryAfterMs() == 0 || m.GetFatal() {
		t.Fatalf("rotation over the session budget answered %v", m)
	}
	if len(f.registrations.calls()) != 0 {
		t.Fatal("a request over the session budget reached the domain")
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
	// A second report within a second is kept, not dropped, and stored
	// when the second ends; a third replaces it.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, report()); err != nil ||
		f.endpoints.stored() != 1 {
		t.Fatalf("fast report: %v, %d stored", err, f.endpoints.stored())
	}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, report(public)); err != nil ||
		f.endpoints.stored() != 1 {
		t.Fatalf("second fast report: %v, %d stored", err, f.endpoints.stored())
	}
	if delay, armed := f.timer.pending(); !armed || delay != endpointReportInterval {
		t.Fatalf("timer %s armed %t, want the rest of the second", delay, armed)
	}
	f.advance(endpointReportInterval)
	f.timer.trigger()
	if f.endpoints.stored() != 2 || len(f.endpoints.sets[1].Endpoints()) != 1 {
		t.Fatalf("kept report: %d stored, want the latest one", f.endpoints.stored())
	}
	if _, armed := f.timer.pending(); armed {
		t.Fatal("timer left armed with nothing waiting")
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

func TestConversationFlushesADeferredEndpointChange(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	if err := f.talk.sink.SendSnapshot(t.Context(), streamFixture(t, 1)); err != nil {
		t.Fatal(err)
	}
	disco := make([]byte, 32)
	disco[0] = 9
	report := &mtcpv1.EndpointReport{DiscoKey: disco, Endpoints: []*mtcpv1.Endpoint{
		{Ip: []byte{198, 51, 100, 7}, Port: 41641, Kind: mtcpv1.Endpoint_SERVER_REFLEXIVE}}}
	// Core stores the change but defers its announcement for 3 s, then for
	// another 1 s when the flush comes a little early.
	f.endpoints.announcement = mapsession.EndpointAnnouncement{Deferred: true, RetryAfter: 3 * time.Second}
	f.endpoints.flushResults = []mapsession.EndpointAnnouncement{{Deferred: true, RetryAfter: time.Second}, {}}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, report); err != nil {
		t.Fatal(err)
	}
	if delay, armed := f.timer.pending(); !armed || delay != 3*time.Second {
		t.Fatalf("timer %s armed %t, want the deferral", delay, armed)
	}
	f.advance(3 * time.Second)
	f.timer.trigger()
	if delay, armed := f.timer.pending(); f.endpoints.flushes != 1 || !armed || delay != time.Second {
		t.Fatalf("after the first flush: %d flushes, timer %s armed %t", f.endpoints.flushes, delay, armed)
	}
	f.advance(time.Second)
	f.timer.trigger()
	if _, armed := f.timer.pending(); f.endpoints.flushes != 2 || armed {
		t.Fatalf("after the announcing flush: %d flushes, armed %t", f.endpoints.flushes, armed)
	}
	// A timer firing early does nothing and waits again.
	f.endpoints.announcement = mapsession.EndpointAnnouncement{Deferred: true, RetryAfter: 2 * time.Second}
	f.advance(endpointReportInterval)
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, report); err != nil {
		t.Fatal(err)
	}
	f.timer.trigger()
	if delay, armed := f.timer.pending(); f.endpoints.flushes != 2 || !armed || delay != 2*time.Second {
		t.Fatalf("early fire: %d flushes, timer %s armed %t", f.endpoints.flushes, delay, armed)
	}
	// Once the session ends nothing is stored or flushed.
	f.talk.stopEndpointPacing()
	f.advance(2 * time.Second)
	f.timer.trigger()
	if f.endpoints.flushes != 2 {
		t.Fatal("a flush ran after the session ended")
	}
	f.advance(endpointReportInterval)
	stored := f.endpoints.stored()
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, report); err != nil ||
		f.endpoints.stored() != stored {
		t.Fatalf("a report was stored after the session ended: %v", err)
	}
}

func endpointReportFixture(port uint32) *mtcpv1.EndpointReport {
	disco := make([]byte, 32)
	disco[0] = 9
	return &mtcpv1.EndpointReport{DiscoKey: disco, Endpoints: []*mtcpv1.Endpoint{
		{Ip: []byte{198, 51, 100, 7}, Port: port, Kind: mtcpv1.Endpoint_SERVER_REFLEXIVE}}}
}

// storedPort is the port of the latest stored report.
func (endpoints *fakeEndpoints) storedPort() uint16 {
	endpoints.mu.Lock()
	defer endpoints.mu.Unlock()
	if len(endpoints.sets) == 0 {
		return 0
	}
	return endpoints.sets[len(endpoints.sets)-1].Endpoints()[0].Address().Port()
}

func (endpoints *fakeEndpoints) failures(observe []error, flush ...error) {
	endpoints.mu.Lock()
	defer endpoints.mu.Unlock()
	endpoints.observeErrs, endpoints.flushErrs = observe, flush
}

func storeUnavailable() error { return fmt.Errorf("%w: redis timeout", mapsession.ErrEndpointStore) }

func flushUnavailable() error { return fmt.Errorf("%w: redis timeout", mapsession.ErrEndpointFlush) }

// endpointPacingFixture is a conversation with a map and one stored report.
func endpointPacingFixture(t *testing.T) *conversationFixture {
	t.Helper()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	if err := f.talk.sink.SendSnapshot(t.Context(), streamFixture(t, 1)); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *conversationFixture) sendReport(port uint32) {
	f.t.Helper()
	if err := f.talk.Receive(f.t.Context(), sharedmtcp.MessageEndpointReport, endpointReportFixture(port)); err != nil {
		f.t.Fatal(err)
	}
}

func TestConversationRetriesAStoreRedisCouldNotTake(t *testing.T) {
	t.Parallel()
	f := endpointPacingFixture(t)
	// A store that fails is kept and retried after 1 s, then 2 s, until it is
	// stored: a Redis failover never loses the latest report.
	f.endpoints.failures([]error{storeUnavailable(), storeUnavailable()})
	f.sendReport(1001)
	for attempt, want := range []time.Duration{time.Second, 2 * time.Second} {
		delay, armed := f.timer.pending()
		if !armed || delay != want || f.endpoints.stored() != 0 {
			t.Fatalf("after failure %d: timer %s armed %t, %d stored", attempt+1, delay, armed, f.endpoints.stored())
		}
		f.advance(want)
		f.timer.trigger()
	}
	if f.endpoints.stored() != 1 || f.endpoints.attempts != 3 {
		t.Fatalf("stored %d after %d attempts, want the report stored on the third", f.endpoints.stored(),
			f.endpoints.attempts)
	}
	if _, armed := f.timer.pending(); armed {
		t.Fatal("timer still armed after the store")
	}
}

func TestConversationReplacesAFailedReportAndKeepsTheBackoff(t *testing.T) {
	t.Parallel()
	f := endpointPacingFixture(t)
	f.endpoints.failures([]error{storeUnavailable(), storeUnavailable()})
	f.sendReport(1001) // fails; retried in 1 s
	f.advance(time.Second)
	f.timer.trigger() // fails again; the backoff is now 2 s
	f.advance(time.Second)
	f.sendReport(1002) // replaces it, but Redis is still given the backoff
	if delay, armed := f.timer.pending(); !armed || delay != time.Second || f.endpoints.stored() != 0 {
		t.Fatalf("newer report: timer %s armed %t, %d stored", delay, armed, f.endpoints.stored())
	}
	f.advance(time.Second)
	f.timer.trigger()
	if f.endpoints.stored() != 1 || f.endpoints.storedPort() != 1002 || f.endpoints.attempts != 3 {
		t.Fatalf("stored %d (port %d) after %d attempts, want only the newer report", f.endpoints.stored(),
			f.endpoints.storedPort(), f.endpoints.attempts)
	}
}

func TestConversationDropsAReportThatCannotBeStored(t *testing.T) {
	t.Parallel()
	f := endpointPacingFixture(t)
	// A rejected observation is final: it is not retried.
	f.endpoints.failures([]error{errors.Join(mapsession.ErrOpen, mapsession.ErrEndpointObservationRejected)})
	f.sendReport(1001)
	if _, armed := f.timer.pending(); armed || f.endpoints.attempts != 1 {
		t.Fatalf("a rejected report was kept: armed %t, %d attempts", armed, f.endpoints.attempts)
	}
	// A report Redis keeps refusing is given up after endpointRetryAttempts.
	f.advance(time.Second)
	refusals := make([]error, endpointRetryAttempts+1)
	for index := range refusals {
		refusals[index] = storeUnavailable()
	}
	f.endpoints.failures(refusals)
	f.sendReport(1002)
	for range endpointRetryAttempts - 1 {
		delay, armed := f.timer.pending()
		if !armed || delay > endpointRetryLimit {
			t.Fatalf("retry not scheduled: %s %t", delay, armed)
		}
		f.advance(delay)
		f.timer.trigger()
	}
	if _, armed := f.timer.pending(); armed || f.endpoints.attempts != 1+endpointRetryAttempts {
		t.Fatalf("after %d attempts the report is still kept (armed %t)", f.endpoints.attempts, armed)
	}
}

func TestConversationRetriesAFlushRedisCouldNotTake(t *testing.T) {
	t.Parallel()
	f := endpointPacingFixture(t)
	f.endpoints.announcement = mapsession.EndpointAnnouncement{Deferred: true, RetryAfter: time.Second}
	f.endpoints.failures(nil, flushUnavailable())
	f.sendReport(1001)
	f.advance(time.Second)
	f.timer.trigger() // the flush fails
	if delay, armed := f.timer.pending(); f.endpoints.flushes != 1 || !armed || delay != time.Second {
		t.Fatalf("after a failed flush: %d flushes, timer %s armed %t", f.endpoints.flushes, delay, armed)
	}
	f.advance(time.Second)
	f.timer.trigger()
	if _, armed := f.timer.pending(); f.endpoints.flushes != 2 || armed {
		t.Fatalf("after the retried flush: %d flushes, armed %t", f.endpoints.flushes, armed)
	}
	// A flush that is final is not retried; the resync announces the change.
	f.endpoints.failures(nil, errNoSnapshot)
	f.advance(time.Second)
	f.sendReport(1002)
	f.advance(time.Second)
	f.timer.trigger()
	if _, armed := f.timer.pending(); f.endpoints.flushes != 3 || armed {
		t.Fatalf("after a final flush failure: %d flushes, armed %t", f.endpoints.flushes, armed)
	}
}

// TestConversationKeepsAReportThatArrivesDuringAStore runs a timer-fired
// store and a report from the session at once: the report is kept and the
// timer re-armed for it when the store ends.
func TestConversationKeepsAReportThatArrivesDuringAStore(t *testing.T) {
	t.Parallel()
	f := endpointPacingFixture(t)
	f.sendReport(1001) // stored at once
	f.advance(100 * time.Millisecond)
	f.sendReport(1002) // kept for the end of the second
	block, entered := make(chan struct{}), make(chan struct{})
	f.endpoints.mu.Lock()
	f.endpoints.block, f.endpoints.entered = block, entered
	f.endpoints.mu.Unlock()
	f.advance(900 * time.Millisecond)
	fired := make(chan struct{})
	go func() {
		defer close(fired)
		f.timer.trigger() // stores 1002 and blocks in Redis
	}()
	<-entered
	f.sendReport(1003) // busy: kept without waiting for the store
	if f.endpoints.stored() != 1 {
		t.Fatalf("%d stored while the store is blocked", f.endpoints.stored())
	}
	close(block)
	<-fired
	delay, armed := f.timer.pending()
	if f.endpoints.stored() != 2 || f.endpoints.storedPort() != 1002 || !armed || delay != time.Second {
		t.Fatalf("after the store: %d stored (port %d), timer %s armed %t", f.endpoints.stored(),
			f.endpoints.storedPort(), delay, armed)
	}
	f.advance(time.Second)
	f.timer.trigger()
	if f.endpoints.stored() != 3 || f.endpoints.storedPort() != 1003 {
		t.Fatalf("the report kept during the store was lost: %d stored (port %d)", f.endpoints.stored(),
			f.endpoints.storedPort())
	}
}

// TestConversationEndOfSessionWaitsForAStore ends the session while a
// store runs: the end waits for it, and nothing starts afterwards.
func TestConversationEndOfSessionWaitsForAStore(t *testing.T) {
	t.Parallel()
	f := endpointPacingFixture(t)
	f.sendReport(1001)
	f.advance(100 * time.Millisecond)
	f.sendReport(1002)
	block, entered := make(chan struct{}), make(chan struct{})
	f.endpoints.mu.Lock()
	f.endpoints.block, f.endpoints.entered = block, entered
	f.endpoints.mu.Unlock()
	f.advance(900 * time.Millisecond)
	go f.timer.trigger()
	<-entered
	f.sendReport(1003) // kept, and dropped when the session ends
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		f.talk.stopEndpointPacing()
	}()
	select {
	case <-stopped:
		t.Fatal("the session ended before its store")
	case <-time.After(20 * time.Millisecond): //nolint:forbidigo // a stop that returns early would be seen here
	}
	close(block)
	<-stopped
	if _, armed := f.timer.pending(); armed || f.endpoints.stored() != 2 {
		t.Fatalf("after the end: %d stored, armed %t", f.endpoints.stored(), armed)
	}
	f.sendReport(1004)
	if f.endpoints.stored() != 2 {
		t.Fatal("a report was stored after the session ended")
	}
}

func TestEndpointReportBelongsToItsStream(t *testing.T) {
	t.Parallel()
	reported := snapshotGenerationFixture(t, 1, 3)
	if !sameStream(snapshotGenerationFixture(t, 2, 3), reported) {
		t.Fatal("a new revision of the same stream rejected the report")
	}
	if sameStream(snapshotGenerationFixture(t, 1, 4), reported) {
		t.Fatal("a report of an older session generation was accepted")
	}
}

func TestEndpointBackoffDoublesUpToItsLimit(t *testing.T) {
	t.Parallel()
	for failures, want := range map[int]time.Duration{1: time.Second, 2: 2 * time.Second, 5: 16 * time.Second,
		6: endpointRetryLimit, 100: endpointRetryLimit} {
		if got := endpointBackoff(failures); got != want {
			t.Fatalf("endpointBackoff(%d) = %s, want %s", failures, got, want)
		}
	}
}

func TestConversationDropsEndpointsPeersMustNotProbe(t *testing.T) {
	t.Parallel()
	f := endpointPacingFixture(t)
	f.talk.application.options.DeniedEndpointPrefixes = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	endpoint := func(address string) *mtcpv1.Endpoint {
		parsed := netip.MustParseAddrPort(address)
		return &mtcpv1.Endpoint{Ip: parsed.Addr().AsSlice(), Port: uint32(parsed.Port()), Kind: mtcpv1.Endpoint_HOST}
	}
	report := endpointReportFixture(41641) // 198.51.100.7, kept
	report.Endpoints = append(report.Endpoints,
		endpoint("100.64.0.1:41641"),         // the Device's own overlay address
		endpoint("100.100.1.1:41641"),        // another overlay address
		endpoint("192.0.2.10:3478"),          // a relay
		endpoint("[2001:db8::10]:3478"),      // a relay over IPv6
		endpoint("203.0.113.5:443"),          // the operator's denied range
		endpoint("[64:ff9b::c000:20a]:3478"), // the relay through NAT64
		endpoint("192.168.1.20:41641"),       // LAN, kept
		endpoint("[fd12:3456::7]:41641"),     // LAN ULA, kept
	)
	// An IPv4-mapped address is held to the IPv4 rules.
	report.Endpoints = append(report.Endpoints, &mtcpv1.Endpoint{
		Ip: netip.MustParseAddr("::ffff:203.0.113.6").AsSlice(), Port: 443, Kind: mtcpv1.Endpoint_HOST,
	})
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, report); err != nil {
		t.Fatal(err)
	}
	f.endpoints.mu.Lock()
	defer f.endpoints.mu.Unlock()
	if len(f.endpoints.sets) != 1 {
		t.Fatalf("%d stored, want one report", len(f.endpoints.sets))
	}
	var got []string
	for _, stored := range f.endpoints.sets[0].Endpoints() {
		got = append(got, stored.Address().String())
	}
	want := []string{"192.168.1.20:41641", "198.51.100.7:41641", "[fd12:3456::7]:41641"}
	if !slices.Equal(got, want) {
		t.Fatalf("stored %v, want %v", got, want)
	}
}

func TestApplicationValidatesDeniedEndpointPrefixes(t *testing.T) {
	t.Parallel()
	for _, prefixes := range [][]netip.Prefix{
		{netip.MustParsePrefix("0.0.0.0/0")},
		{netip.PrefixFrom(netip.MustParseAddr("203.0.113.5"), 24)},
		{netip.MustParsePrefix("::ffff:203.0.113.0/120")},
		make([]netip.Prefix, maxDeniedEndpointPrefixes+1),
	} {
		if validDeniedEndpointPrefixes(prefixes) {
			t.Fatalf("validDeniedEndpointPrefixes(%v) = true", prefixes)
		}
	}
	if !validDeniedEndpointPrefixes([]netip.Prefix{netip.MustParsePrefix("203.0.113.10/32")}) ||
		!validDeniedEndpointPrefixes(nil) {
		t.Fatal("a valid list was refused")
	}
}

func TestEndpointFilterDropsTheDevicesOwnOverlayAndInfrastructure(t *testing.T) {
	t.Parallel()
	filter := newEndpointFilter(relayDirectoryFixture(t), []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")})
	overlay := []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"), netip.MustParsePrefix("fd7a:115c:a1e0::1/128")}
	for address, allowed := range map[string]bool{
		"fd7a:115c:a1e0::1":  false, // the Device's own IPv6 overlay address
		"fd7a:115c:a1e0::2":  true,  // another address of that range: the node drops its peers' own
		"192.0.2.10":         false, // relay
		"2001:db8::10":       false, // relay over IPv6
		"64:ff9b::c000:20a":  false, // relay through NAT64
		"203.0.113.77":       false, // denied
		"64:ff9b::cb00:714d": false, // denied through NAT64
		"198.51.100.7":       true,
		"64:ff9b::c633:6407": true, // 198.51.100.7 through NAT64
	} {
		if got := filter.allows(netip.MustParseAddr(address), overlay); got != allowed {
			t.Errorf("allows(%s) = %t, want %t", address, got, allowed)
		}
	}
}

// TestMapEncodingDropsStoredEndpointsPeersMustNotProbe checks the second
// application of the filter: an endpoint stored before its relay or denied
// range was known is not sent in the map either.
func TestMapEncodingDropsStoredEndpointsPeersMustNotProbe(t *testing.T) {
	t.Parallel()
	snapshot := streamFixture(t, 1)
	peer := snapshot.AuthorizedPeers()[0]
	disco := must(node.NewDiscoveryKey([32]byte{7}))
	var stored []node.Endpoint
	for _, address := range []string{"192.0.2.10:3478", "203.0.113.9:41641", "198.51.100.7:41641"} {
		stored = append(stored, must(node.NewEndpoint(netip.MustParseAddrPort(address), node.EndpointSourceSTUN)))
	}
	connectivity := []mapsession.Connectivity{
		must(mapsession.NewConnectivity(mapsession.ConnectivityParams{
			Key:    must(mapsession.NewConnectivityKey(snapshot.NodeID(), snapshot.SessionGeneration())),
			Online: true,
		})),
		must(mapsession.NewConnectivity(mapsession.ConnectivityParams{
			Key:         must(mapsession.NewConnectivityKey(peer.NodeID(), peer.SessionGeneration())),
			EndpointSet: must(node.NewEndpointSet(disco, stored)), EndpointSetPresent: true, Online: true,
		})),
	}
	snapshot = must(snapshot.WithConnectivity(connectivity))
	message, err := encodeSnapshot(snapshot, &mtcpv1.View{Epoch: 1, Seq: 1}, false,
		[]netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}, dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	endpoints := message.GetPeers()[0].GetEndpoints()
	if len(endpoints) != 1 || !bytes.Equal(endpoints[0].GetIp(), []byte{198, 51, 100, 7}) {
		t.Fatalf("peer endpoints = %v, want only 198.51.100.7", endpoints)
	}
}

func TestConversationLimitsMapResyncs(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	if err := f.talk.sink.SendSnapshot(t.Context(), streamFixture(t, 1)); err != nil {
		t.Fatal(err)
	}
	// The first snapshot follows the session's key and relay messages.
	for {
		if got, _ := f.next(); got == sharedmtcp.MessageMapSnapshot {
			break
		}
	}
	resync := &mtcpv1.MapResync{View: &mtcpv1.View{}}
	for attempt := range resyncBurst {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageMapResync, resync); err != nil {
			t.Fatalf("resync %d: %v", attempt+1, err)
		}
		f.expect(sharedmtcp.MessageMapSnapshot)
	}
	// One more is a node that does not follow the protocol: the session
	// ends, and the node reconnects for a fresh snapshot.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageMapResync, resync); !errors.Is(err, errSessionLimited) {
		t.Fatalf("resync over the limit: %v", err)
	}
	failure, _ := f.expect(sharedmtcp.MessageError).(*mtcpv1.Error)
	if failure.GetCode() != mtcpv1.Error_OVERLOADED || !failure.GetFatal() || failure.GetRetryAfterMs() != 5000 {
		t.Fatalf("resync over the limit answered %v", failure)
	}
}

func TestConversationLimitsEnforcementReports(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	f.talk.nodeKey = node.Key(f.session.Hello().GetNodeKey())
	report := func(grants uint32) *mtcpv1.EnforcementReport {
		digest := make([]byte, 32)
		digest[0] = 1
		return &mtcpv1.EnforcementReport{Digest: digest, Grants: grants, AppliedMs: f.now().UnixMilli()}
	}
	stored := func() []uint32 {
		f.streams.mu.Lock()
		defer f.streams.mu.Unlock()
		var grants []uint32
		for _, stored := range f.streams.reports {
			grants = append(grants, uint32(stored.Filter.Grants())) //nolint:gosec // small test values
		}
		return grants
	}
	for grants := range uint32(enforcementBurst + 3) {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEnforcementReport, report(grants+1)); err != nil {
			t.Fatal(err)
		}
	}
	// The burst is stored at once; of the rest only the latest is kept, and
	// it is stored when a token is back.
	if got := stored(); len(got) != enforcementBurst {
		t.Fatalf("stored %v at once, want the first %d", got, enforcementBurst)
	}
	delay, armed := f.enforcementTimer.pending()
	if !armed || delay != time.Second {
		t.Fatalf("timer %s armed %t, want a second", delay, armed)
	}
	f.advance(time.Second)
	f.enforcementTimer.trigger()
	got := stored()
	if len(got) != enforcementBurst+1 || got[len(got)-1] != enforcementBurst+3 {
		t.Fatalf("stored %v, want the latest report last", got)
	}
	if _, armed := f.enforcementTimer.pending(); armed {
		t.Fatal("timer still armed with nothing kept")
	}
	// The end of the session drops a kept report.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEnforcementReport, report(99)); err != nil {
		t.Fatal(err)
	}
	f.talk.stopEnforcementPacing()
	f.advance(time.Minute)
	f.enforcementTimer.trigger()
	if got := stored(); got[len(got)-1] == 99 {
		t.Fatal("a report was stored after the session ended")
	}
}

func TestConversationLimitsBrowserSignIns(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessageRegisterRequest)
	f.run()
	for attempt := range browserBurst {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest,
			f.request(4, interactiveAuth(""))); err != nil {
			t.Fatalf("sign-in %d: %v", attempt+1, err)
		}
		if f.expect(sharedmtcp.MessageRegisterResponse).(*mtcpv1.RegisterResponse).GetPending() == nil {
			t.Fatalf("sign-in %d got no approval URL", attempt+1)
		}
	}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, f.request(4, interactiveAuth(""))); err != nil {
		t.Fatal(err)
	}
	failure, _ := f.expect(sharedmtcp.MessageError).(*mtcpv1.Error)
	if failure.GetCode() != mtcpv1.Error_OVERLOADED || failure.GetFatal() || failure.GetRetryAfterMs() != 10000 {
		t.Fatalf("a sign-in over the limit answered %v", failure)
	}
}

func enforcementReportFixture(grants uint32) *mtcpv1.EnforcementReport {
	digest := make([]byte, 32)
	digest[0] = 1
	return &mtcpv1.EnforcementReport{Digest: digest, Grants: grants, AppliedMs: 1_800_000_000_000}
}

func (f *conversationFixture) storedGrants() []int {
	f.streams.mu.Lock()
	defer f.streams.mu.Unlock()
	grants := make([]int, 0, len(f.streams.reports))
	for _, stored := range f.streams.reports {
		grants = append(grants, stored.Filter.Grants())
	}
	return grants
}

// TestEnforcementPacingKeepsReportsThatArriveDuringAStore runs a store
// that blocks in Redis while more reports arrive, then ends the session
// during another store.
func TestEnforcementPacingKeepsReportsThatArriveDuringAStore(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	f.talk.nodeKey = node.Key(f.session.Hello().GetNodeKey())
	block, entered := make(chan struct{}), make(chan struct{})
	f.streams.mu.Lock()
	f.streams.block, f.streams.entered = block, entered
	f.streams.mu.Unlock()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = f.talk.Receive(t.Context(), sharedmtcp.MessageEnforcementReport, enforcementReportFixture(1))
	}()
	<-entered
	// A store is in flight: these are kept, the latest replacing the other.
	for _, grants := range []uint32{2, 3} {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEnforcementReport,
			enforcementReportFixture(grants)); err != nil {
			t.Fatal(err)
		}
	}
	close(block)
	<-done
	if got := f.storedGrants(); !slices.Equal(got, []int{1, 3}) {
		t.Fatalf("stored %v, want the first and then the latest", got)
	}
	// The end of the session waits for a store in flight.
	block, entered = make(chan struct{}), make(chan struct{})
	f.streams.mu.Lock()
	f.streams.block, f.streams.entered = block, entered
	f.streams.mu.Unlock()
	go func() {
		_ = f.talk.Receive(t.Context(), sharedmtcp.MessageEnforcementReport, enforcementReportFixture(4))
	}()
	<-entered
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		f.talk.stopEnforcementPacing()
	}()
	select {
	case <-stopped:
		t.Fatal("the session ended before its store")
	case <-time.After(20 * time.Millisecond): //nolint:forbidigo // a stop that returns early would be seen here
	}
	close(block)
	<-stopped
}

func TestEnforcementPacingDropsAReportOfAnOldKey(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	f.talk.nodeKey = node.Key(f.session.Hello().GetNodeKey())
	for grants := range uint32(enforcementBurst + 1) {
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEnforcementReport,
			enforcementReportFixture(grants+1)); err != nil {
			t.Fatal(err)
		}
	}
	// The kept report describes the old key's filter.
	f.talk.mu.Lock()
	f.talk.nodeKey = node.Key{9}
	f.talk.mu.Unlock()
	f.advance(time.Second)
	f.enforcementTimer.trigger()
	if got := f.storedGrants(); len(got) != enforcementBurst {
		t.Fatalf("stored %v, want the kept report of the old key dropped", got)
	}
}

func TestConversationResyncBudgetRecovers(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, sharedmtcp.MessagePing)
	now := f.now()
	for range resyncBurst {
		if _, ok := f.talk.resync.spend(now, 1); !ok {
			t.Fatal("burst refused")
		}
	}
	if _, ok := f.talk.resync.spend(now.Add(5*time.Second-time.Millisecond), 1); ok {
		t.Fatal("a resync before 5 s admitted")
	}
	if _, ok := f.talk.resync.spend(now.Add(5*time.Second), 1); !ok {
		t.Fatal("a resync after 5 s refused")
	}
}

func TestPresenceChurnAsksTheNodeToWait(t *testing.T) {
	t.Parallel()
	err := &mapsession.PresenceChurnError{RetryAfter: 42 * time.Second}
	lifecycle := lifecycleFor(err)
	if lifecycle.GetState() != mtcpv1.Lifecycle_RECONNECT || lifecycle.GetRetryAfterMs() != 42_000 {
		t.Fatalf("lifecycle = %v, want RECONNECT after 42 s", lifecycle)
	}
	if reason := streamEndReason(err); reason != "presence_churn" {
		t.Fatalf("end reason = %q", reason)
	}
}

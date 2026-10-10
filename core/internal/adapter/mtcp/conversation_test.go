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
	"meshtransit.net/core/internal/domain/node"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// fakeStreams sends one snapshot, then ends the stream with end.
type fakeStreams struct {
	snapshot mapsession.Snapshot
	end      error

	mu       sync.Mutex
	requests []mapsession.Request
	reports  []mapsession.ClientEnforcement
}

func (streams *fakeStreams) Serve(ctx context.Context, _ control.AuthenticatedMachine, request mapsession.Request,
	sink mapsession.StreamSink) error {
	streams.mu.Lock()
	streams.requests = append(streams.requests, request)
	streams.mu.Unlock()
	if err := sink.SendSnapshot(ctx, streams.snapshot); err != nil {
		return err
	}
	return streams.end
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

type conversationFixture struct {
	node      *nodeView
	streams   *fakeStreams
	endpoints *fakeEndpoints
	clock     time.Time
	talk      *conversation
}

func newConversationFixture(t *testing.T, end error) *conversationFixture {
	t.Helper()
	session, view, control := testSession(t)
	f := &conversationFixture{node: view, streams: &fakeStreams{snapshot: streamFixture(t, 1), end: end},
		endpoints: &fakeEndpoints{}, clock: time.Unix(1_800_000_000, 0)}
	application, err := NewApplication(f.streams, f.endpoints,
		[]ControlKey{{Private: control, NotAfter: f.clock.Add(time.Hour)}}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	application.now = func() time.Time { return f.clock }
	f.talk, _ = application.Open(session).(*conversation)
	return f
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

func TestConversationRunSendsLifecycleWhenTheStreamEnds(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, mapsession.ErrUnauthorized)
	if err := f.talk.Run(t.Context()); !errors.Is(err, mapsession.ErrUnauthorized) {
		t.Fatalf("Run = %v", err)
	}
	types := f.node.messages()
	want := []sharedmtcp.MessageType{sharedmtcp.MessageKeyUpdate, sharedmtcp.MessageMapSnapshot,
		sharedmtcp.MessageLifecycle}
	if len(types) != len(want) {
		t.Fatalf("messages %v, want %v", types, want)
	}
	for i := range want {
		if types[i] != want[i] {
			t.Fatalf("messages %v, want %v", types, want)
		}
	}
	if len(f.streams.requests) != 1 || f.streams.requests[0].NodeKey() != node.Key(f.talk.session.Hello().GetNodeKey()) {
		t.Fatal("the stream did not serve the hello's node key")
	}
}

func TestConversationEndpointReports(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, nil)
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
	f.clock = f.clock.Add(endpointReportInterval)
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
		f.clock = f.clock.Add(endpointReportInterval)
		var violation protocolError
		if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEndpointReport, bad); !errors.As(err, &violation) {
			t.Errorf("%s: %v, want a violation", name, err)
		}
	}
}

func TestConversationEnforcementAndUnsupportedMessages(t *testing.T) {
	t.Parallel()
	f := newConversationFixture(t, nil)
	digest := make([]byte, 32)
	digest[0] = 1
	report := &mtcpv1.EnforcementReport{Digest: digest, Grants: 4, AppliedMs: f.clock.UnixMilli()}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEnforcementReport, report); err != nil {
		t.Fatal(err)
	}
	if len(f.streams.reports) != 1 || f.streams.reports[0].Filter.Grants() != 4 ||
		!f.streams.reports[0].AppliedAt.Equal(time.UnixMilli(f.clock.UnixMilli())) {
		t.Fatalf("enforcement reports %v", f.streams.reports)
	}
	// Malformed evidence is ignored, never stored.
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageEnforcementReport,
		&mtcpv1.EnforcementReport{Digest: []byte{1}, AppliedMs: 1}); err != nil || len(f.streams.reports) != 1 {
		t.Fatalf("malformed report: %v, %d stored", err, len(f.streams.reports))
	}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageRegisterRequest, &mtcpv1.RegisterRequest{}); err != nil {
		t.Fatalf("register must not end the session: %v", err)
	}
	if typ, message, _ := f.node.read(); typ != sharedmtcp.MessageError ||
		message.(*mtcpv1.Error).GetCode() != mtcpv1.Error_UNSUPPORTED || message.(*mtcpv1.Error).GetFatal() {
		t.Fatalf("register answered %#x %v", uint8(typ), message)
	}
	var violation protocolError
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageMapSnapshot, &mtcpv1.MapSnapshot{}); !errors.As(err, &violation) {
		t.Fatalf("a Core-only message from a node: %v", err)
	}
}

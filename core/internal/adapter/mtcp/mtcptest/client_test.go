package mtcptest

import (
	"context"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	mtcpadapter "meshtransit.net/core/internal/adapter/mtcp"
	"meshtransit.net/core/internal/platform/clientip"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const (
	testCredential = "mtc1.test.secret"
	testDeviceID   = "01890f00-0000-7000-8000-000000000701"
	testNetworkID  = "01890f00-0000-7000-8000-000000000201"
)

var testExpiry = time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)

// fakeCore is a Core application behind the real MTCP server: it
// authorizes testCredential, streams a one-Device map and keeps the last
// endpoint report across sessions, like Core's endpoint store.
type fakeCore struct {
	control    key.ControlPrivate
	reconnects atomic.Int32  // Lifecycle RECONNECTs still to send before a map
	epochs     atomic.Uint64 // the last map epoch of any session

	mu        sync.Mutex
	nodeKey   []byte
	endpoints *mtcpv1.EndpointReport
}

type fakeConversation struct {
	core    *fakeCore
	session *mtcpadapter.Session

	mu         sync.Mutex
	epoch, seq uint64
}

func (core *fakeCore) Open(session *mtcpadapter.Session) mtcpadapter.Conversation {
	return &fakeConversation{core: core, session: session}
}

func (conversation *fakeConversation) Run(ctx context.Context) error {
	if conversation.session.OpenedBy() == sharedmtcp.MessagePing {
		if conversation.core.reconnects.Add(-1) >= 0 {
			_ = conversation.session.Send(sharedmtcp.MessageLifecycle,
				&mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_RECONNECT, RetryAfterMs: 10})
			return nil
		}
		if err := conversation.sendMap(); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return nil
}

func (conversation *fakeConversation) Receive(_ context.Context, _ sharedmtcp.MessageType, message proto.Message) error {
	core := conversation.core
	switch m := message.(type) {
	case *mtcpv1.RegisterRequest:
		if m.GetAuth().GetEnrollmentKey() != testCredential {
			return conversation.session.Send(sharedmtcp.MessageRegisterResponse, &mtcpv1.RegisterResponse{
				Outcome: &mtcpv1.RegisterResponse_Rejected_{Rejected: &mtcpv1.RegisterResponse_Rejected{
					Code: mtcpv1.RegisterResponse_Rejected_CREDENTIAL_INVALID}}})
		}
		if !conversation.session.VerifyKeyProof(m.GetNodeKey(), m.GetNodeKeyProof()) ||
			!conversation.session.VerifyKeyProof(m.GetDiscoKey(), m.GetDiscoKeyProof()) ||
			m.GetHostinfo().GetHostname() != "node.example" {
			return mtcpadapter.Violation(mtcpv1.Error_INVALID, "bad registration")
		}
		core.mu.Lock()
		core.nodeKey = m.GetNodeKey()
		core.mu.Unlock()
		if err := conversation.session.Send(sharedmtcp.MessageRegisterResponse, &mtcpv1.RegisterResponse{
			Outcome: &mtcpv1.RegisterResponse_Authorized_{Authorized: &mtcpv1.RegisterResponse_Authorized{
				DeviceId: testDeviceID, NetworkId: testNetworkID, Addresses: [][]byte{{100, 64, 0, 7}},
				KeyExpiryMs: testExpiry.UnixMilli()}}}); err != nil {
			return err
		}
		return conversation.sendMap()
	case *mtcpv1.EndpointReport:
		// Like Core's endpoint store, an unchanged report wakes nothing.
		core.mu.Lock()
		unchanged := core.endpoints != nil && slices.EqualFunc(core.endpoints.GetEndpoints(), m.GetEndpoints(),
			func(a, b *mtcpv1.Endpoint) bool { return proto.Equal(a, b) })
		core.endpoints = m
		core.mu.Unlock()
		if unchanged {
			return nil
		}
		return conversation.sendSelf()
	}
	return nil
}

func (conversation *fakeConversation) self() *mtcpv1.Device {
	core := conversation.core
	core.mu.Lock()
	defer core.mu.Unlock()
	device := &mtcpv1.Device{DeviceId: testDeviceID, Name: "node.example.", DisplayName: "node.example",
		NodeKey: core.nodeKey, Addresses: [][]byte{{100, 64, 0, 7}},
		AllowedPrefixes: []*mtcpv1.Prefix{sharedmtcp.AppendPrefix(netip.MustParsePrefix("100.64.0.7/32"))},
		KeyExpiryMs:     testExpiry.UnixMilli()}
	if core.endpoints != nil {
		device.DiscoKey, device.Endpoints = core.endpoints.GetDiscoKey(), core.endpoints.GetEndpoints()
	}
	return device
}

func (conversation *fakeConversation) sendMap() error {
	conversation.mu.Lock()
	defer conversation.mu.Unlock()
	if err := conversation.session.Send(sharedmtcp.MessageKeyUpdate, &mtcpv1.KeyUpdate{
		ControlKeys: []*mtcpv1.KeyUpdate_ControlKey{{Key: conversation.controlPublic()}}, Nonce: []byte("n"),
	}); err != nil {
		return err
	}
	conversation.epoch, conversation.seq = conversation.core.epochs.Add(1), 1
	return conversation.session.Send(sharedmtcp.MessageMapSnapshot, &mtcpv1.MapSnapshot{
		View: &mtcpv1.View{Epoch: conversation.epoch, Seq: 1}, Self: conversation.self(),
		NetworkRevisions: []*mtcpv1.NetworkRevision{{NetworkId: testNetworkID, Revision: 7}},
		PacketFilter:     &mtcpv1.PacketFilter{}, Dns: &mtcpv1.DnsConfig{},
	})
}

func (conversation *fakeConversation) sendSelf() error {
	conversation.mu.Lock()
	defer conversation.mu.Unlock()
	if conversation.epoch == 0 {
		return nil
	}
	conversation.seq++
	return conversation.session.Send(sharedmtcp.MessageMapDelta, &mtcpv1.MapDelta{
		View: &mtcpv1.View{Epoch: conversation.epoch, Seq: conversation.seq}, Self: conversation.self(),
	})
}

func (conversation *fakeConversation) controlPublic() []byte {
	public := conversation.core.control.Public()
	return public[:]
}

func newTestClient(t *testing.T) (*Client, *fakeCore) {
	t.Helper()
	control, err := key.NewControlPrivate(nil)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := clientip.NewResolver(nil)
	if err != nil {
		t.Fatal(err)
	}
	core := &fakeCore{control: control}
	server, err := mtcpadapter.NewServer(mtcpadapter.Options{
		Keys:      []mtcpadapter.ControlKey{{Private: control, NotAfter: testExpiry}},
		ClientIPs: resolver, Handler: core, Logger: slog.New(slog.DiscardHandler), Metrics: mtcpadapter.NewMetrics(),
		Capabilities: []string{"map.zstd"},
	})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewTLSServer(server)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Error("shutdown:", err)
		}
		httpServer.Close()
	})
	client, err := NewClient(Options{
		ControlAddress: httpServer.Listener.Addr().String(), TLSServerName: "example.com",
		RootCAPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: httpServer.Certificate().Raw}),
		Hostname:  "node.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	return client, core
}

func TestClientRegistersAndConvergesMaps(t *testing.T) {
	client, core := newTestClient(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	registration, err := client.Register(ctx, testCredential)
	if err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	want := Registration{DeviceID: testDeviceID, NetworkID: testNetworkID,
		Addresses: []netip.Addr{netip.MustParseAddr("100.64.0.7")}, KeyExpiry: testExpiry}
	if !reflect.DeepEqual(registration, want) {
		t.Fatalf("Register() = %+v, want %+v", registration, want)
	}
	if pinned := client.PinnedControlKey(); pinned.Public != core.control.Public() || !pinned.NotAfter.Equal(testExpiry) {
		t.Fatalf("PinnedControlKey() = %+v", pinned)
	}
	replay, err := client.Register(ctx, testCredential)
	if err != nil || !reflect.DeepEqual(replay, registration) {
		t.Fatalf("replayed Register() = (%+v, %v), want %+v", replay, err, registration)
	}

	// The first map session converges through a delta; the next snapshot
	// already carries the stored report.
	converged, err := client.FetchFullMap(ctx)
	if err != nil {
		t.Fatalf("FetchFullMap() error = %v", err)
	}
	connectivity := client.Connectivity()
	identity := client.Identity()
	if converged.DeviceID != testDeviceID || converged.NodeKey != identity.NodeKey ||
		converged.DiscoveryKey != connectivity.DiscoveryKey || !slices.Equal(converged.Endpoints, connectivity.Endpoints) ||
		!converged.DenyAll || converged.PeerCount != 0 || converged.Addresses[0] != netip.MustParsePrefix("100.64.0.7/32") {
		t.Fatalf("FetchFullMap() = %+v", converged)
	}
	initial, err := client.FetchInitialStreamMap(ctx)
	if err != nil || !reflect.DeepEqual(initial, converged) {
		t.Fatalf("FetchInitialStreamMap() = (%+v, %v), want %+v", initial, err, converged)
	}

	stream, opened, err := client.OpenMapStream(ctx)
	if err != nil || !opened.Snapshot || !reflect.DeepEqual(opened.Map, converged) ||
		opened.NetworkRevisions[testNetworkID] != 7 {
		t.Fatalf("OpenMapStream() = (%+v, %v)", opened, err)
	}
	defer func() { _ = stream.Close() }()
	endpoint := netip.MustParseAddrPort("198.51.100.20:41641")
	if err := client.UpdateEndpoint(endpoint); err != nil {
		t.Fatal(err)
	}
	if err := stream.ReportEndpoints(ctx); err != nil {
		t.Fatalf("ReportEndpoints() error = %v", err)
	}
	advanced, err := stream.Next(ctx)
	if err != nil || advanced.Snapshot || !advanced.SelfChanged ||
		!slices.Equal(advanced.Map.Endpoints, []netip.AddrPort{endpoint}) || len(advanced.PeersUpserted) != 0 {
		t.Fatalf("Next() = (%+v, %v)", advanced, err)
	}
}

func TestClientRetriesReconnectBeforeFirstMap(t *testing.T) {
	client, core := newTestClient(t)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if _, err := client.Register(ctx, testCredential); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	core.reconnects.Store(2)
	if _, err := client.FetchInitialStreamMap(ctx); err != nil {
		t.Fatalf("FetchInitialStreamMap() after RECONNECT error = %v", err)
	}
	if core.reconnects.Load() >= 0 {
		t.Fatalf("reconnects left = %d, want both consumed", core.reconnects.Load())
	}
}

func TestClientReportsRejectedRegistration(t *testing.T) {
	client, _ := newTestClient(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := client.Register(ctx, "mtc1.other.secret"); !errors.Is(err, ErrRegistration) {
		t.Fatalf("Register() error = %v, want ErrRegistration", err)
	}
	if _, err := client.Register(ctx, "bad\ncredential"); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("Register() error = %v, want ErrInvalidClient", err)
	}
}

func TestMapStateRejectsInconsistentStreams(t *testing.T) {
	self := &mtcpv1.Device{DeviceId: testDeviceID, NodeKey: make([]byte, 32)}
	snapshot := func(epoch uint64, peers ...string) *mtcpv1.MapSnapshot {
		message := &mtcpv1.MapSnapshot{View: &mtcpv1.View{Epoch: epoch, Seq: 1}, Self: self,
			PacketFilter: &mtcpv1.PacketFilter{}, Dns: &mtcpv1.DnsConfig{}}
		for _, peer := range peers {
			message.Peers = append(message.Peers, &mtcpv1.Device{DeviceId: peer, NodeKey: make([]byte, 32)})
		}
		return message
	}
	delta := func(epoch, seq uint64, mutate func(*mtcpv1.MapDelta)) *mtcpv1.MapDelta {
		message := &mtcpv1.MapDelta{View: &mtcpv1.View{Epoch: epoch, Seq: seq}}
		if mutate != nil {
			mutate(message)
		}
		return message
	}
	tests := []struct {
		name    string
		delta   *mtcpv1.MapDelta
		applied bool
		wantErr bool
	}{
		{name: "next seq", delta: delta(5, 2, nil), applied: true},
		{name: "older epoch dropped", delta: delta(4, 2, nil)},
		{name: "gap", delta: delta(5, 3, nil), wantErr: true},
		{name: "unknown patch", delta: delta(5, 2, func(m *mtcpv1.MapDelta) {
			m.PeerPatches = []*mtcpv1.PeerPatch{{DeviceId: "c"}}
		}), wantErr: true},
		{name: "upsert and remove", delta: delta(5, 2, func(m *mtcpv1.MapDelta) {
			m.PeersUpsert = []*mtcpv1.Device{{DeviceId: "a"}}
			m.PeersRemove = []string{"a"}
		}), wantErr: true},
		{name: "remove", delta: delta(5, 2, func(m *mtcpv1.MapDelta) { m.PeersRemove = []string{"b"} }), applied: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := newMapState()
			if _, err := state.applySnapshot(snapshot(5, "a", "b")); err != nil {
				t.Fatal(err)
			}
			_, applied, err := state.applyDelta(test.delta)
			if applied != test.applied || (err != nil) != test.wantErr {
				t.Fatalf("applyDelta() = (%t, %v), want (%t, error %t)", applied, err, test.applied, test.wantErr)
			}
		})
	}
	state := newMapState()
	if _, err := state.applySnapshot(snapshot(5, "b", "a")); !errors.Is(err, ErrMap) {
		t.Fatalf("unsorted snapshot error = %v, want ErrMap", err)
	}
	if _, err := state.applySnapshot(snapshot(5)); err != nil {
		t.Fatal(err)
	}
	if _, err := state.applySnapshot(snapshot(5)); !errors.Is(err, ErrMap) {
		t.Fatalf("same-epoch snapshot error = %v, want ErrMap", err)
	}
}

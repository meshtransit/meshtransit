package mtcpclient

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
	"meshtransit.net/shared/policydigest"
)

// streamCore scripts one map session per call of script.
type streamCore struct {
	*fakeCore
	mu       sync.Mutex
	received []proto.Message
	sessions atomic.Int32
	disco    []byte // the node's session disco key, as its options name it
}

// snapshot is snapshotMessage whose self entry carries the node's disco key,
// as Core's map does once it has the node's EndpointReport.
func (core *streamCore) snapshot(epoch uint64) *mtcpv1.MapSnapshot {
	message := snapshotMessage(epoch)
	core.mu.Lock()
	message.Self.DiscoKey = append([]byte(nil), core.disco...)
	core.mu.Unlock()
	return message
}

func newStreamCore(t *testing.T, script func(core *streamCore, s *coreSession, index int32)) *streamCore {
	core := &streamCore{fakeCore: newFakeCore(t)}
	core.set(func(fake *fakeCore) {
		fake.serve = func(s *coreSession) {
			if _, first, err := s.receive(5 * time.Second); err != nil {
				return
			} else if _, ok := first.(*mtcpv1.Ping); !ok {
				return
			}
			script(core, s, core.sessions.Add(1))
		}
	})
	return core
}

// expect reads until a message of type want arrives, recording all.
func (core *streamCore) expect(s *coreSession, want sharedmtcp.MessageType) proto.Message {
	for {
		t, message, err := s.receive(5 * time.Second)
		if err != nil {
			return nil
		}
		core.mu.Lock()
		core.received = append(core.received, message)
		core.mu.Unlock()
		if t == want {
			return message
		}
	}
}

func (core *streamCore) keyUpdate(s *coreSession) {
	public := s.control.Public()
	_ = s.send(sharedmtcp.MessageKeyUpdate, &mtcpv1.KeyUpdate{
		Nonce:       []byte("n1"),
		ControlKeys: []*mtcpv1.KeyUpdate_ControlKey{{Key: public[:], NotAfterMs: time.Now().Add(time.Hour).UnixMilli()}},
	})
}

func (core *streamCore) options(t *testing.T) (controlplane.KeyMaterial, controlplane.NetmapOptions) {
	t.Helper()
	material, options := streamOptions(t, core.fakeCore)
	raw, err := parseDiscoKey(options.PeerProbePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	core.mu.Lock()
	core.disco = append([]byte(nil), raw[:]...)
	core.mu.Unlock()
	return material, options
}

func streamOptions(t *testing.T, core *fakeCore) (controlplane.KeyMaterial, controlplane.NetmapOptions) {
	t.Helper()
	trustCore := core.client()
	var serve func(*coreSession)
	core.set(func(fake *fakeCore) { serve, fake.serve = fake.serve, answerPings })
	trust, err := trustCore.BootstrapTrust(t.Context(), core.origin(), controlplane.ControlKeyFingerprint(core.controlKey().Public()))
	core.set(func(fake *fakeCore) { fake.serve = serve })
	if err != nil {
		t.Fatal(err)
	}
	disco, _ := key.NewDiscoPrivate()
	public := disco.Public()
	return trust.Material, controlplane.NetmapOptions{
		Hostname: "laptop", PinnedFingerprint: trust.Fingerprint,
		PeerProbePublicKey: "discokey:" + bytesHexOf(public[:]),
	}
}

func bytesHexOf(raw []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(raw))
	for i, b := range raw {
		out[2*i], out[2*i+1] = digits[b>>4], digits[b&15]
	}
	return string(out)
}

func TestStreamNetmapDeliversMapsAndReports(t *testing.T) {
	t.Parallel()
	deliveredDelta := make(chan struct{})
	core := newStreamCore(t, func(core *streamCore, s *coreSession, _ int32) {
		core.keyUpdate(s)
		// Core's first map names no disco key for this session yet.
		_ = s.send(sharedmtcp.MessageMapSnapshot, snapshotMessage(10))
		core.expect(s, sharedmtcp.MessageMapAck)
		report, ok := core.expect(s, sharedmtcp.MessageEndpointReport).(*mtcpv1.EndpointReport)
		if !ok {
			return
		}
		self := snapshotMessage(10).GetSelf()
		self.DiscoKey = report.GetDiscoKey()
		_ = s.send(sharedmtcp.MessageMapDelta, &mtcpv1.MapDelta{View: &mtcpv1.View{Epoch: 10, Seq: 2}, Self: self})
		core.expect(s, sharedmtcp.MessageMapAck)
		_ = s.send(sharedmtcp.MessageMapDelta, &mtcpv1.MapDelta{
			View:        &mtcpv1.View{Epoch: 10, Seq: 3},
			PeersRemove: []string{"peer-b"},
		})
		core.expect(s, sharedmtcp.MessageMapAck)
		<-deliveredDelta
		// A gap asks for a resync; the answer is a new epoch.
		_ = s.send(sharedmtcp.MessageMapDelta, &mtcpv1.MapDelta{View: &mtcpv1.View{Epoch: 10, Seq: 9}})
		resync, ok := core.expect(s, sharedmtcp.MessageMapResync).(*mtcpv1.MapResync)
		if !ok || resync.GetView().GetSeq() != 3 {
			return
		}
		_ = s.send(sharedmtcp.MessageMapSnapshot, core.snapshot(11))
		core.expect(s, sharedmtcp.MessageMapAck)
		_ = s.send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_SUSPENDED})
		answerPings(s)
	})
	material, options := core.options(t)
	var snapshots []networkmap.Snapshot
	var once sync.Once
	err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
		func(_ context.Context, snapshot networkmap.Snapshot) error {
			snapshots = append(snapshots, snapshot)
			if len(snapshots) == 2 {
				once.Do(func() { close(deliveredDelta) })
			}
			return nil
		})
	if !errors.Is(err, controlplane.ErrNetmapAuthorityPaused) {
		t.Fatalf("StreamNetmap = %v, want paused", err)
	}
	// The first map waited for the self entry with this session's disco key.
	if len(snapshots) != 3 || len(snapshots[0].Peers) != 2 || len(snapshots[1].Peers) != 1 || len(snapshots[2].Peers) != 2 ||
		snapshots[0].Self.DiscoveryKey != options.PeerProbePublicKey || snapshots[2].Revision <= snapshots[1].Revision {
		t.Fatalf("%d snapshots delivered", len(snapshots))
	}
	core.mu.Lock()
	defer core.mu.Unlock()
	var pong, report bool
	for _, message := range core.received {
		switch m := message.(type) {
		case *mtcpv1.Pong:
			pong = pong || string(m.GetNonce()) == "n1"
		case *mtcpv1.EndpointReport:
			report = report || len(m.GetDiscoKey()) == 32
		}
	}
	if !pong || !report {
		t.Fatalf("KeyUpdate acknowledged %t, endpoint report sent %t", pong, report)
	}
	// The map stream declares that this client applies large maps.
	if !slices.ContainsFunc(core.hello, func(hello *mtcpv1.ClientHello) bool { return slices.Contains(hello.GetCapabilities(), "map.large1") }) {
		t.Fatal("the map stream did not declare map.large1")
	}
}

func TestStreamNetmapSendsEnforcementEvidence(t *testing.T) {
	t.Parallel()
	received := make(chan *mtcpv1.EnforcementReport, 1)
	core := newStreamCore(t, func(core *streamCore, s *coreSession, _ int32) {
		core.keyUpdate(s)
		_ = s.send(sharedmtcp.MessageMapSnapshot, core.snapshot(1))
		if report, ok := core.expect(s, sharedmtcp.MessageEnforcementReport).(*mtcpv1.EnforcementReport); ok {
			received <- report
		}
		_ = s.send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_REVOKED})
		answerPings(s)
	})
	material, options := core.options(t)
	enforcement := make(chan controlplane.EnforcementReport, 1)
	options.EnforcementReports = enforcement
	err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
		func(context.Context, networkmap.Snapshot) error {
			enforcement <- controlplane.EnforcementReport{Digest: policydigest.Digest{1}, Grants: 2, AppliedAt: time.Now()}
			return nil
		})
	if !errors.Is(err, controlplane.ErrNetmapAuthorityRevoked) {
		t.Fatalf("StreamNetmap = %v", err)
	}
	select {
	case report := <-received:
		if report.GetGrants() != 2 || report.GetDigest()[0] != 1 {
			t.Fatalf("enforcement report %v", report)
		}
	default:
		t.Fatal("no enforcement report reached Core")
	}
}

func TestStreamNetmapRouterOffersAndReportsRouteDigest(t *testing.T) {
	t.Parallel()
	offers := make(chan *mtcpv1.HostinfoReport, 1)
	reports := make(chan *mtcpv1.EnforcementReport, 1)
	core := newStreamCore(t, func(core *streamCore, s *coreSession, _ int32) {
		core.keyUpdate(s)
		_ = s.send(sharedmtcp.MessageMapSnapshot, core.snapshot(1))
		if offer, ok := core.expect(s, sharedmtcp.MessageHostinfoReport).(*mtcpv1.HostinfoReport); ok {
			offers <- offer
		}
		if report, ok := core.expect(s, sharedmtcp.MessageEnforcementReport).(*mtcpv1.EnforcementReport); ok {
			reports <- report
		}
		_ = s.send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_REVOKED})
		answerPings(s)
	})
	material, options := core.options(t)
	advertised := make(chan []netip.Prefix, 1)
	advertised <- []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}
	enforcement := make(chan controlplane.EnforcementReport, 1)
	options.EnableSubnetRouter, options.AdvertisedRoutes, options.EnforcementReports = true, advertised, enforcement
	err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
		func(context.Context, networkmap.Snapshot) error {
			enforcement <- controlplane.EnforcementReport{
				Digest: policydigest.Digest{1}, RouteDigest: policydigest.Digest{2},
				RouteEntries: 1, AppliedAt: time.Now(),
			}
			return nil
		})
	if !errors.Is(err, controlplane.ErrNetmapAuthorityRevoked) {
		t.Fatalf("StreamNetmap = %v", err)
	}
	if !slices.ContainsFunc(core.hello, func(hello *mtcpv1.ClientHello) bool {
		return slices.Contains(hello.GetCapabilities(), "router.subnet.v1")
	}) {
		t.Fatal("the map stream did not declare router.subnet.v1")
	}
	select {
	case offer := <-offers:
		prefixes := offer.GetHostinfo().GetAdvertisedPrefixes()
		if len(prefixes) != 1 || prefixes[0].GetBits() != 16 {
			t.Fatalf("offer = %v", offer)
		}
	default:
		t.Fatal("no offer reached Core")
	}
	select {
	case report := <-reports:
		if len(report.GetRouteDigest()) != 32 || report.GetRouteDigest()[0] != 2 || report.GetRouteEntries() != 1 {
			t.Fatalf("enforcement report %v", report)
		}
	default:
		t.Fatal("no enforcement report reached Core")
	}
}

func TestStreamNetmapReconnectsAndEndsOnRevocation(t *testing.T) {
	t.Parallel()
	core := newStreamCore(t, func(core *streamCore, s *coreSession, index int32) {
		core.keyUpdate(s)
		_ = s.send(sharedmtcp.MessageMapSnapshot, core.snapshot(uint64(max(index, 1))))
		core.expect(s, sharedmtcp.MessageMapAck)
		if index == 1 {
			return // the session drops; the node reconnects
		}
		_ = s.send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_LOGGED_OUT})
		answerPings(s)
	})
	material, options := core.options(t)
	var connection []bool
	options.ConnectionChanged = func(connected bool) { connection = append(connection, connected) }
	delivered := 0
	err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
		func(context.Context, networkmap.Snapshot) error { delivered++; return nil })
	if !errors.Is(err, controlplane.ErrNetmapAuthorityRevoked) || core.sessions.Load() != 2 || delivered < 1 {
		t.Fatalf("StreamNetmap = %v after %d sessions, %d deliveries", err, core.sessions.Load(), delivered)
	}
	// Connected, lost when the first session dropped, connected again on the
	// second session's map; a permanent end reports nothing more.
	if len(connection) != 3 || !connection[0] || connection[1] || !connection[2] {
		t.Fatalf("connection changes = %v, want [true false true]", connection)
	}
}

func TestStreamNetmapRefusesAnotherControlKey(t *testing.T) {
	t.Parallel()
	core := newStreamCore(t, func(_ *streamCore, s *coreSession, _ int32) {
		other, _ := key.NewControlPrivate(nil)
		public := other.Public()
		_ = s.send(sharedmtcp.MessageKeyUpdate, &mtcpv1.KeyUpdate{
			ControlKeys: []*mtcpv1.KeyUpdate_ControlKey{{Key: public[:], NotAfterMs: time.Now().Add(time.Hour).UnixMilli()}},
		})
		answerPings(s)
	})
	material, options := core.options(t)
	err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
		func(context.Context, networkmap.Snapshot) error { return nil })
	if !errors.Is(err, controlplane.ErrControlKeyChanged) {
		t.Fatalf("StreamNetmap = %v", err)
	}
}

func TestStreamNetmapConsumerFailureIsPermanent(t *testing.T) {
	t.Parallel()
	core := newStreamCore(t, func(core *streamCore, s *coreSession, _ int32) {
		core.keyUpdate(s)
		_ = s.send(sharedmtcp.MessageMapSnapshot, core.snapshot(1))
		answerPings(s)
	})
	material, options := core.options(t)
	err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
		func(context.Context, networkmap.Snapshot) error { return errors.New("data plane failed") })
	if !errors.Is(err, controlplane.ErrNetmapConsumer) || core.sessions.Load() != 1 {
		t.Fatalf("StreamNetmap = %v", err)
	}
}

func TestStreamNetmapSendsPathStats(t *testing.T) {
	t.Parallel()
	received := make(chan *mtcpv1.PathStatsReport, 1)
	core := newStreamCore(t, func(core *streamCore, s *coreSession, _ int32) {
		core.keyUpdate(s)
		_ = s.send(sharedmtcp.MessageMapSnapshot, core.snapshot(1))
		if report, ok := core.expect(s, sharedmtcp.MessagePathStatsReport).(*mtcpv1.PathStatsReport); ok {
			received <- report
		}
		_ = s.send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_REVOKED})
		answerPings(s)
	})
	material, options := core.options(t)
	paths := make(chan controlplane.PathStatsReport, 1)
	options.PathStats = paths
	start := time.Now()
	err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
		func(context.Context, networkmap.Snapshot) error {
			paths <- controlplane.PathStatsReport{
				IntervalStart: start, Interval: time.Minute,
				Peers: []controlplane.PeerPathStats{{
					DeviceID: "peer-a", Path: controlplane.PathRelay, RelayRegion: 1,
					RelayReason: controlplane.RelayNoResponse, RelayTxBytes: 42,
				}},
			}
			return nil
		})
	if !errors.Is(err, controlplane.ErrNetmapAuthorityRevoked) {
		t.Fatalf("StreamNetmap = %v", err)
	}
	select {
	case report := <-received:
		peer := report.GetPeers()[0]
		if report.GetIntervalS() != 60 || peer.GetDeviceId() != "peer-a" || peer.GetTechnique() != mtcpv1.PeerPathStats_RELAY ||
			peer.GetRelayRegion() != 1 || peer.GetRelayReason() != mtcpv1.PeerPathStats_NO_RESPONSE || peer.GetRelayTxBytes() != 42 {
			t.Fatalf("path stats %v", report)
		}
	default:
		t.Fatal("no path stats reached Core")
	}
}

func TestStreamNetmapStagesAndFollowsTheNextControlKey(t *testing.T) {
	t.Parallel()
	next, _ := key.NewControlPrivate(nil)
	nextPublic := next.Public()
	core := newStreamCore(t, func(core *streamCore, s *coreSession, _ int32) {
		current := s.control.Public()
		later := time.Now().Add(time.Hour).UnixMilli()
		_ = s.send(sharedmtcp.MessageKeyUpdate, &mtcpv1.KeyUpdate{Nonce: []byte("n1"), ControlKeys: []*mtcpv1.KeyUpdate_ControlKey{
			{Key: current[:], NotAfterMs: later}, {Key: nextPublic[:], NotAfterMs: later + 1},
		}})
		if core.expect(s, sharedmtcp.MessagePong) == nil {
			return
		}
		// Core now answers only with the next key.
		_ = s.send(sharedmtcp.MessageKeyUpdate, &mtcpv1.KeyUpdate{Nonce: []byte("n2"), ControlKeys: []*mtcpv1.KeyUpdate_ControlKey{
			{Key: nextPublic[:], NotAfterMs: later + 1},
		}})
		answerPings(s)
	})
	material, options := core.options(t)
	var staged [][]byte
	options.ControlKeysChanged = func(_ context.Context, announced []byte) error {
		staged = append(staged, append([]byte(nil), announced...))
		return nil
	}
	err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
		func(context.Context, networkmap.Snapshot) error { return nil })
	if !errors.Is(err, controlplane.ErrControlKeyRotated) {
		t.Fatalf("StreamNetmap = %v, want ErrControlKeyRotated", err)
	}
	if len(staged) != 1 || string(staged[0]) != string(controlplane.EncodeControlPublicKey(nextPublic)) {
		t.Fatalf("staged next keys = %q", staged)
	}
}

// TestStreamNetmapBatchesMapAcks checks mtcp-v1 §7.2: a snapshot is
// acknowledged at once, deltas once ackBatch of them wait, and the rest
// ackDelay after the first of them.
func TestStreamNetmapBatchesMapAcks(t *testing.T) {
	t.Parallel()
	type ack struct {
		seq uint64
		at  time.Duration
	}
	acks := make(chan []ack, 1)
	core := newStreamCore(t, func(core *streamCore, s *coreSession, _ int32) {
		core.keyUpdate(s)
		_ = s.send(sharedmtcp.MessageMapSnapshot, snapshotMessage(10))
		core.expect(s, sharedmtcp.MessageMapAck)
		report, ok := core.expect(s, sharedmtcp.MessageEndpointReport).(*mtcpv1.EndpointReport)
		if !ok {
			return
		}
		self := snapshotMessage(10).GetSelf()
		self.DiscoKey = report.GetDiscoKey()
		start := time.Now()
		_ = s.send(sharedmtcp.MessageMapDelta, &mtcpv1.MapDelta{View: &mtcpv1.View{Epoch: 10, Seq: 2}, Self: self})
		for seq := uint64(3); seq <= 7; seq++ {
			_ = s.send(sharedmtcp.MessageMapDelta, &mtcpv1.MapDelta{View: &mtcpv1.View{Epoch: 10, Seq: seq}})
		}
		var got []ack
		for range 2 {
			if message, ok := core.expect(s, sharedmtcp.MessageMapAck).(*mtcpv1.MapAck); ok {
				got = append(got, ack{seq: message.GetView().GetSeq(), at: time.Since(start)})
			}
		}
		acks <- got
		_ = s.send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_SUSPENDED})
		answerPings(s)
	})
	material, options := core.options(t)
	err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
		func(context.Context, networkmap.Snapshot) error { return nil })
	if !errors.Is(err, controlplane.ErrNetmapAuthorityPaused) {
		t.Fatalf("StreamNetmap = %v, want paused", err)
	}
	got := <-acks
	if len(got) != 2 || got[0].seq != 5 || got[0].at >= ackDelay || got[1].seq != 7 || got[1].at < ackDelay {
		t.Fatalf("acks %+v, want seq 5 at once and seq 7 after %s", got, ackDelay)
	}
}

// TestStreamNetmapHandsCoresWaitToTheDaemon ends a stream with SUSPENDED
// and a retry_after: the daemon, which decides what follows, gets the wait.
func TestStreamNetmapHandsCoresWaitToTheDaemon(t *testing.T) {
	t.Parallel()
	core := newStreamCore(t, func(core *streamCore, s *coreSession, _ int32) {
		core.keyUpdate(s)
		_ = s.send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{
			State:        mtcpv1.Lifecycle_SUSPENDED,
			RetryAfterMs: 7000,
		})
		answerPings(s)
	})
	material, options := core.options(t)
	err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
		func(context.Context, networkmap.Snapshot) error { return nil })
	if !errors.Is(err, controlplane.ErrNetmapAuthorityPaused) || controlplane.RetryAfterOf(err) != 7*time.Second {
		t.Fatalf("StreamNetmap = %v, wait %s; want paused with 7s", err, controlplane.RetryAfterOf(err))
	}
}

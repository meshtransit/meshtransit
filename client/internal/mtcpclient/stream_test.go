package mtcpclient

import (
	"context"
	"errors"
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
	core := newStreamCore(t, func(core *streamCore, s *coreSession, index int32) {
		core.keyUpdate(s)
		_ = s.send(sharedmtcp.MessageMapSnapshot, snapshotMessage(10))
		core.expect(s, sharedmtcp.MessageMapAck)
		core.expect(s, sharedmtcp.MessageEndpointReport)
		_ = s.send(sharedmtcp.MessageMapDelta, &mtcpv1.MapDelta{
			View:        &mtcpv1.View{Epoch: 10, Seq: 2},
			PeersRemove: []string{"peer-b"},
		})
		core.expect(s, sharedmtcp.MessageMapAck)
		<-deliveredDelta
		// A gap asks for a resync; the answer is a new epoch.
		_ = s.send(sharedmtcp.MessageMapDelta, &mtcpv1.MapDelta{View: &mtcpv1.View{Epoch: 10, Seq: 9}})
		resync, ok := core.expect(s, sharedmtcp.MessageMapResync).(*mtcpv1.MapResync)
		if !ok || resync.GetView().GetSeq() != 2 {
			return
		}
		_ = s.send(sharedmtcp.MessageMapSnapshot, snapshotMessage(11))
		core.expect(s, sharedmtcp.MessageMapAck)
		_ = s.send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_SUSPENDED})
		answerPings(s)
	})
	material, options := streamOptions(t, core.fakeCore)
	enforcement := make(chan controlplane.EnforcementReport, 1)
	options.EnforcementReports = enforcement
	var snapshots []networkmap.Snapshot
	var once sync.Once
	err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
		func(_ context.Context, snapshot networkmap.Snapshot) error {
			snapshots = append(snapshots, snapshot)
			if len(snapshots) == 1 {
				enforcement <- controlplane.EnforcementReport{Digest: policydigest.Digest{1}, Grants: 2, AppliedAt: time.Now()}
			}
			if len(snapshots) == 2 {
				once.Do(func() { close(deliveredDelta) })
			}
			return nil
		})
	if !errors.Is(err, controlplane.ErrNetmapAuthorityPaused) {
		t.Fatalf("StreamNetmap = %v, want paused", err)
	}
	if len(snapshots) != 3 || len(snapshots[0].Peers) != 2 || len(snapshots[1].Peers) != 1 || len(snapshots[2].Peers) != 2 ||
		snapshots[2].Revision <= snapshots[1].Revision {
		t.Fatalf("%d snapshots delivered", len(snapshots))
	}
	core.mu.Lock()
	defer core.mu.Unlock()
	var pong, report, enforced bool
	for _, message := range core.received {
		switch m := message.(type) {
		case *mtcpv1.Pong:
			pong = pong || string(m.GetNonce()) == "n1"
		case *mtcpv1.EndpointReport:
			report = report || len(m.GetDiscoKey()) == 32
		case *mtcpv1.EnforcementReport:
			enforced = enforced || m.GetGrants() == 2
		}
	}
	if !pong || !report {
		t.Fatalf("KeyUpdate acknowledged %t, endpoint report sent %t", pong, report)
	}
	_ = enforced // timing: the report may follow the resync
}

func TestStreamNetmapReconnectsAndEndsOnRevocation(t *testing.T) {
	t.Parallel()
	core := newStreamCore(t, func(core *streamCore, s *coreSession, index int32) {
		core.keyUpdate(s)
		_ = s.send(sharedmtcp.MessageMapSnapshot, snapshotMessage(uint64(max(index, 1))))
		core.expect(s, sharedmtcp.MessageMapAck)
		if index == 1 {
			return // the session drops; the node reconnects
		}
		_ = s.send(sharedmtcp.MessageLifecycle, &mtcpv1.Lifecycle{State: mtcpv1.Lifecycle_LOGGED_OUT})
		answerPings(s)
	})
	material, options := streamOptions(t, core.fakeCore)
	delivered := 0
	err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
		func(context.Context, networkmap.Snapshot) error { delivered++; return nil })
	if !errors.Is(err, controlplane.ErrNetmapAuthorityRevoked) || core.sessions.Load() != 2 || delivered < 1 {
		t.Fatalf("StreamNetmap = %v after %d sessions, %d deliveries", err, core.sessions.Load(), delivered)
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
	material, options := streamOptions(t, core.fakeCore)
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
		_ = s.send(sharedmtcp.MessageMapSnapshot, snapshotMessage(1))
		answerPings(s)
	})
	material, options := streamOptions(t, core.fakeCore)
	err := core.client().StreamNetmap(t.Context(), core.origin(), material, options,
		func(context.Context, networkmap.Snapshot) error { return errors.New("data plane failed") })
	if !errors.Is(err, controlplane.ErrNetmapConsumer) || core.sessions.Load() != 1 {
		t.Fatalf("StreamNetmap = %v", err)
	}
}

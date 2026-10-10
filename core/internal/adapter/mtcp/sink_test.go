package mtcp

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// pipeTransport captures records a Session writes.
type pipeTransport struct {
	mu      sync.Mutex
	records [][]byte
	signal  chan struct{}
}

func (p *pipeTransport) ReadRecord(time.Time) (sharedmtcp.RecordType, []byte, error) {
	select {}
}

func (p *pipeTransport) WriteRecord(_ sharedmtcp.RecordType, body []byte, _ time.Time) error {
	p.mu.Lock()
	p.records = append(p.records, append([]byte(nil), body...))
	p.mu.Unlock()
	select {
	case p.signal <- struct{}{}:
	default:
	}
	return nil
}

func (p *pipeTransport) Close() error { return nil }

// nodeView decrypts what Core sent, as the node would.
type nodeView struct {
	t         *testing.T
	transport *pipeTransport
	noise     *sharedmtcp.Session
	asm       *sharedmtcp.Assembler
	next      int
}

func (view *nodeView) messages() []sharedmtcp.MessageType {
	view.t.Helper()
	var types []sharedmtcp.MessageType
	for {
		t, _, ok := view.read()
		if !ok {
			return types
		}
		types = append(types, t)
	}
}

func (view *nodeView) read() (sharedmtcp.MessageType, proto.Message, bool) {
	view.t.Helper()
	for {
		view.transport.mu.Lock()
		if view.next >= len(view.transport.records) {
			view.transport.mu.Unlock()
			return 0, nil, false
		}
		record := view.transport.records[view.next]
		view.next++
		view.transport.mu.Unlock()
		fragment, err := view.noise.Open(nil, record)
		if err != nil {
			view.t.Fatal(err)
		}
		t, payload, complete, err := view.asm.Add(fragment)
		if err != nil {
			view.t.Fatal(err)
		}
		if complete {
			message, err := sharedmtcp.DecodeMessage(t, payload)
			if err != nil {
				view.t.Fatal(err)
			}
			return t, message, true
		}
	}
}

func testSession(t *testing.T) (*Session, *nodeView, key.ControlPrivate) {
	t.Helper()
	control, _ := key.NewControlPrivate(nil)
	machine, _ := key.NewMachinePrivate(nil)
	client, init, err := sharedmtcp.StartClient(sharedmtcp.ClientConfig{Machine: machine, Control: control.Public(),
		Hello: &mtcpv1.ClientHello{ProtocolVersion: 1, TimestampMs: time.Now().UnixMilli(), NodeKey: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	server, _ := sharedmtcp.ReadInit(control, init, nil)
	reply := &mtcpv1.ServerHello{ProtocolVersion: 1, SessionId: make([]byte, 16), Capabilities: []string{"map.zstd"}}
	coreNoise, response, _ := server.Respond(reply)
	nodeNoise, _, err := client.Finish(response)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewServer(Options{Keys: []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}},
		Handler: &recordingHandler{}, Logger: slog.New(slog.DiscardHandler), Metrics: NewMetrics()})
	if err != nil {
		t.Fatal(err)
	}
	transport := &pipeTransport{signal: make(chan struct{}, 1)}
	session := newSession(owner, transport, coreNoise, server.Machine(), server.Hello(), reply)
	return session, &nodeView{t: t, transport: transport, noise: nodeNoise,
		asm: sharedmtcp.NewAssembler(sharedmtcp.CoreToNode)}, control
}

func TestSinkSendsKeysFirstThenSnapshotAndDeltas(t *testing.T) {
	session, node, control := testSession(t)
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	initial := streamFixture(t, 7)
	if err := sink.SendSnapshot(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	keys, _, _ := node.read()
	snapshotType, message, _ := node.read()
	if keys != sharedmtcp.MessageKeyUpdate || snapshotType != sharedmtcp.MessageMapSnapshot {
		t.Fatalf("first messages %#x, %#x; want KeyUpdate then MapSnapshot", uint8(keys), uint8(snapshotType))
	}
	view := message.(*mtcpv1.MapSnapshot).GetView()
	if view.GetSeq() != 1 || view.GetEpoch() == 0 {
		t.Fatalf("snapshot view %v", view)
	}
	next := streamFixture(t, 8)
	delta := must(mapsession.NewAuthorityDelta(initial, next))
	if err := sink.SendAuthorityDelta(t.Context(), delta); err != nil {
		t.Fatal(err)
	}
	deltaType, deltaMessage, _ := node.read()
	if deltaType != sharedmtcp.MessageMapDelta {
		t.Fatalf("got %#x, want MapDelta", uint8(deltaType))
	}
	deltaView := deltaMessage.(*mtcpv1.MapDelta).GetView()
	if deltaView.GetEpoch() != view.GetEpoch() || deltaView.GetSeq() != 2 ||
		deltaMessage.(*mtcpv1.MapDelta).GetPacketFilter() == nil {
		t.Fatalf("delta view %v (want epoch %d seq 2) or no filter", deltaView, view.GetEpoch())
	}
	// A resync of the current epoch gets a fresh snapshot with a newer epoch.
	if err := sink.resync(t.Context(), deltaView); err != nil {
		t.Fatal(err)
	}
	resyncType, resynced, _ := node.read()
	if resyncType != sharedmtcp.MessageMapSnapshot || resynced.(*mtcpv1.MapSnapshot).GetView().GetEpoch() <= view.GetEpoch() {
		t.Fatal("resync did not answer with a newer snapshot")
	}
	if err := sink.SendAuthorityPause(t.Context(), next); err != nil {
		t.Fatal(err)
	}
	pauseType, pause, _ := node.read()
	if pauseType != sharedmtcp.MessageLifecycle || pause.(*mtcpv1.Lifecycle).GetState() != mtcpv1.Lifecycle_SUSPENDED {
		t.Fatalf("pause sent %#x %v", uint8(pauseType), pause)
	}
	if extra := node.messages(); len(extra) != 0 {
		t.Fatalf("unexpected messages %v (KeyUpdate must not repeat while keys are unchanged)", extra)
	}
}

func TestSinkWindowWaitsForAcknowledgements(t *testing.T) {
	session, node, control := testSession(t)
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	current := streamFixture(t, 1)
	if err := sink.SendSnapshot(t.Context(), current); err != nil {
		t.Fatal(err)
	}
	node.messages()
	for revision := int64(2); revision < 9; revision++ {
		next := streamFixture(t, revision)
		if err := sink.SendAuthorityDelta(t.Context(), must(mapsession.NewAuthorityDelta(current, next))); err != nil {
			t.Fatal(err)
		}
		current = next
	}
	// Eight messages are now unacknowledged: the ninth waits.
	next := streamFixture(t, 9)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := sink.SendAuthorityDelta(ctx, must(mapsession.NewAuthorityDelta(current, next))); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("send past a full window = %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- sink.SendAuthorityDelta(t.Context(), must(mapsession.NewAuthorityDelta(current, next)))
	}()
	sink.ack(&mtcpv1.View{Epoch: sink.epoch, Seq: 4})
	if err := <-done; err != nil {
		t.Fatalf("send after an ack: %v", err)
	}
}

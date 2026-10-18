package mtcp

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/proto"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
	"meshtransit.net/shared/mtrp"
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
	session := newSession(owner, transport, coreNoise, control, server.Machine(), server.Hello(), reply)
	return session, &nodeView{t: t, transport: transport, noise: nodeNoise,
		asm: sharedmtcp.NewAssembler(sharedmtcp.CoreToNode)}, control
}

func TestSinkSnapshotProvesTheSessionsDevice(t *testing.T) {
	session, node, control := testSession(t)
	released := 0
	session.releaseSource = func() { released++ }
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	if session.proven.Load() {
		t.Fatal("a session counted as proven before any map")
	}
	if err := sink.SendSnapshot(t.Context(), streamFixture(t, 7)); err != nil {
		t.Fatal(err)
	}
	node.read() // KeyUpdate
	node.read() // MapSnapshot
	if err := sink.SendSnapshot(t.Context(), streamFixture(t, 8)); err != nil {
		t.Fatal(err)
	}
	if !session.proven.Load() || released != 1 {
		t.Fatalf("proven = %t, source released %d times; want true, once", session.proven.Load(), released)
	}
	// The served Device's expiry feeds the expiring-Device gauge.
	if got, want := session.deviceKeyExpiry.Load(), streamFixture(t, 8).KeyExpiry().UnixMilli(); got != want {
		t.Fatalf("session Device expiry = %d, want %d", got, want)
	}
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

// grantFixture is an Interchange grant with one signing key per seed.
func grantFixture(t *testing.T, ticket string, signers ...key.SigningPrivate) mapsession.RelayGrant {
	t.Helper()
	notAfter := time.Now().Add(time.Hour)
	grant := mtrp.InterchangeGrant{RelayMap: []byte("signed relay map"), Ticket: []byte(ticket),
		TicketNotAfter: notAfter}
	for _, signer := range signers {
		grant.SigningKeys = append(grant.SigningKeys, mtrp.TrustedKey{Key: signer.Public(), NotAfter: notAfter})
	}
	payload := must(grant.Marshal())
	return must(mapsession.NewRelayGrant(mapsession.RelayGrantRequest{}, payload, notAfter))
}

func TestSinkDeliversRelayGrants(t *testing.T) {
	session, node, control := testSession(t)
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	signer := must(key.NewSigningPrivate(nil))
	snapshot := streamFixture(t, 1).WithRelayGrant(grantFixture(t, "ticket-1", signer))
	if err := sink.SendSnapshot(t.Context(), snapshot); err != nil {
		t.Fatal(err)
	}
	_, keys, _ := node.read()
	signing := keys.(*mtcpv1.KeyUpdate).GetSigningKeys()
	signerPublic := signer.Public()
	if len(signing) != 1 || string(signing[0].GetKey()) != string(signerPublic[:]) {
		t.Fatalf("KeyUpdate signing keys %v", signing)
	}
	_, mapped, _ := node.read()
	if string(mapped.(*mtcpv1.MapSnapshot).GetRelayMap()) != "signed relay map" {
		t.Fatal("the snapshot does not carry the relay map")
	}
	ticketType, ticket, _ := node.read()
	if ticketType != sharedmtcp.MessageRelayTicket || string(ticket.(*mtcpv1.RelayTicket).GetTicket()) != "ticket-1" {
		t.Fatalf("got %#x %v, want the relay ticket", uint8(ticketType), ticket)
	}
	// A renewed ticket under the same keys and map is just a ticket.
	if err := sink.SendRelayGrant(t.Context(), snapshot.WithRelayGrant(grantFixture(t, "ticket-2", signer))); err != nil {
		t.Fatal(err)
	}
	if types := node.messages(); len(types) != 1 || types[0] != sharedmtcp.MessageRelayTicket {
		t.Fatalf("renewal sent %v, want one RelayTicket", types)
	}
	// A new signing key is announced before the ticket that needs it.
	next := must(key.NewSigningPrivate(nil))
	if err := sink.SendRelayGrant(t.Context(), snapshot.WithRelayGrant(grantFixture(t, "ticket-3", signer, next))); err != nil {
		t.Fatal(err)
	}
	if types := node.messages(); len(types) != 2 || types[0] != sharedmtcp.MessageKeyUpdate ||
		types[1] != sharedmtcp.MessageRelayTicket {
		t.Fatalf("key change sent %v, want KeyUpdate then RelayTicket", types)
	}
}

// TestSinkSendsDNSOnlyWhenItChanged: an authority delta carries DNS only
// when the names it publishes changed (an absent DNS means unchanged).
func TestSinkSendsDNSOnlyWhenItChanged(t *testing.T) {
	session, node, control := testSession(t)
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	scope := snapshotFixture(t, 1).Scope()
	connected := func(revision int64, keyByte byte, peers ...string) mapsession.Snapshot {
		candidates := make([]mapsession.PeerCandidate, 0, len(peers))
		for index, address := range peers {
			candidates = append(candidates, peerFixture(t, scope,
				"01890f00-0000-7000-8000-00000000070"+string(rune('2'+index)), int64(702+index), address, keyByte+byte(index)))
		}
		snapshot := snapshotFixture(t, revision, candidates...)
		connectivity := []mapsession.Connectivity{must(mapsession.NewConnectivity(mapsession.ConnectivityParams{
			Key: must(mapsession.NewConnectivityKey(snapshot.NodeID(), snapshot.SessionGeneration())), Online: true,
		}))}
		for _, peer := range snapshot.AuthorizedPeers() {
			connectivity = append(connectivity, must(mapsession.NewConnectivity(mapsession.ConnectivityParams{
				Key: must(mapsession.NewConnectivityKey(peer.NodeID(), peer.SessionGeneration())), Online: true,
			})))
		}
		return must(snapshot.WithConnectivity(connectivity))
	}
	initial := connected(7, 2, "100.64.0.2")
	if err := sink.SendSnapshot(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	node.messages()
	steps := []struct {
		next    mapsession.Snapshot
		records int // A records the delta carries; -1: no DNS
	}{
		{next: connected(8, 9, "100.64.0.2"), records: -1},              // a peer key changed, not its name
		{next: connected(9, 9, "100.64.0.2", "100.64.0.3"), records: 3}, // a peer joined
		{next: connected(10, 20, "100.64.0.2", "100.64.0.3"), records: -1},
	}
	current := initial
	for index, step := range steps {
		if err := sink.SendAuthorityDelta(t.Context(), must(mapsession.NewAuthorityDelta(current, step.next))); err != nil {
			t.Fatal(err)
		}
		messageType, message, _ := node.read()
		delta, ok := message.(*mtcpv1.MapDelta)
		if messageType != sharedmtcp.MessageMapDelta || !ok {
			t.Fatalf("step %d sent %#x", index, uint8(messageType))
		}
		if got := len(delta.GetDns().GetRecords()); (delta.GetDns() == nil) != (step.records < 0) ||
			step.records >= 0 && got != step.records {
			t.Fatalf("step %d DNS = %v, want %d records", index, delta.GetDns(), step.records)
		}
		current = step.next
	}
}

// TestSinkSendsMapsWithUnlabeledDevicesAndCountsThem: a Device without a DNS
// label is sent unnamed, and the map still goes out.
func TestSinkSendsMapsWithUnlabeledDevicesAndCountsThem(t *testing.T) {
	session, node, control := testSession(t)
	sink := newMapSink(session, false, []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}}, time.Now)
	sink.metrics = NewMetrics()
	scope := snapshotFixture(t, 1).Scope()
	labeled := peerFixture(t, scope, "01890f00-0000-7000-8000-000000000702", 702, "100.64.0.2", 2)
	createdAt := time.Date(2026, time.September, 14, 3, 0, 0, 0, time.UTC)
	unlabeled := must(mapsession.NewPeerCandidate(mapsession.PeerCandidateParams{
		NumericNodeID: labeled.NumericNodeID(), NumericOwnerID: labeled.NumericOwnerID(), Scope: scope,
		NodeID: labeled.NodeID(), OwnerID: labeled.OwnerID(), Hostname: labeled.Hostname(),
		MachineKey: labeled.MachineKey(), NodeKey: labeled.NodeKey(), SessionGeneration: 1,
		Addresses: labeled.Addresses(), CreatedAt: createdAt, KeyExpiry: createdAt.Add(24 * time.Hour),
	}))
	if err := sink.SendSnapshot(t.Context(), snapshotFixture(t, 7, unlabeled)); err != nil {
		t.Fatalf("a Device without a label failed the map: %v", err)
	}
	node.read() // KeyUpdate
	_, message, _ := node.read()
	snapshot, ok := message.(*mtcpv1.MapSnapshot)
	if !ok || len(snapshot.GetPeers()) != 1 || snapshot.GetPeers()[0].GetName() != "peer-2.example." ||
		len(snapshot.GetDns().GetRecords()) != 1 {
		t.Fatalf("map = %v", message)
	}
	registry := prometheus.NewRegistry()
	registry.MustRegister(sink.metrics.Collectors()...)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "meshtransit_mtcp_map_names_degraded_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metric.GetLabel()[0].GetValue() == namesUnlabeled && metric.GetCounter().GetValue() == 1 {
				return
			}
		}
	}
	t.Fatal("the unlabeled Device was not counted")
}

package mtcpclient

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

func testAuditBatch(id byte, intents ...byte) controlplane.KubeAuditBatch {
	batch := controlplane.KubeAuditBatch{ID: [16]byte{id}}
	for _, intent := range intents {
		batch.Intents = append(batch.Intents, controlplane.KubeAuditIntent{ID: [16]byte{intent},
			Peer: "01890f00-0000-7000-8000-000000000702", Groups: []string{"view"}, Class: "write", Verb: "delete",
			Resource: "pods", Namespace: "default", Name: "web-0", ObservedAt: time.Now()})
	}
	return batch
}

// A gateway's operation batches go on the session of its map stream once
// the map arrived; each is answered by the ack naming it, result by result;
// reports go unanswered; a session that ends answers the batches still
// waiting (mtcp-v1 §6.10).
func TestGatewayStreamRecordsOperations(t *testing.T) {
	t.Parallel()
	reported := make(chan *mtcpv1.KubeAuditOutcomes, 1)
	waiting := make(chan struct{}, 1)
	disco, _ := key.NewDiscoPrivate()
	discoKey := disco.Public()
	core := provingCore(t, nil, func(s *coreSession) {
		if _, first, err := s.receive(5 * time.Second); err != nil {
			return
		} else if _, ok := first.(*mtcpv1.Ping); !ok {
			return
		}
		public := s.control.Public()
		_ = s.send(sharedmtcp.MessageKeyUpdate, &mtcpv1.KeyUpdate{
			Nonce:       []byte("n1"),
			ControlKeys: []*mtcpv1.KeyUpdate_ControlKey{{Key: public[:], NotAfterMs: time.Now().Add(time.Hour).UnixMilli()}},
		})
		snapshot := snapshotMessage(10)
		snapshot.Self.DiscoKey = discoKey[:]
		_ = s.send(sharedmtcp.MessageMapSnapshot, snapshot)
		for {
			_, message, err := s.receive(5 * time.Second)
			if err != nil {
				return
			}
			switch m := message.(type) {
			case *mtcpv1.KubeAuditIntents:
				intents := m.GetIntents()
				if m.GetBatchId()[0] == 3 {
					waiting <- struct{}{} // left unanswered until the session ends
					continue
				}
				if m.GetBatchId()[0] == 4 {
					// Acked after the call's deadline: its record was never
					// forwarded (review b2 M1).
					time.Sleep(300 * time.Millisecond)
					_ = s.send(sharedmtcp.MessageKubeAuditAck, &mtcpv1.KubeAuditAck{BatchId: m.GetBatchId(),
						Results: []*mtcpv1.KubeAuditResult{{IntentId: intents[0].GetIntentId(),
							AuditId: bytes.Repeat([]byte{8}, 16)}}})
					continue
				}
				// An ack naming another batch answers nothing.
				_ = s.send(sharedmtcp.MessageKubeAuditAck, &mtcpv1.KubeAuditAck{BatchId: bytes.Repeat([]byte{9}, 16)})
				results := []*mtcpv1.KubeAuditResult{
					{IntentId: intents[0].GetIntentId(), AuditId: bytes.Repeat([]byte{7}, 16)},
					{IntentId: intents[1].GetIntentId(), Refused: "limited", RetryAfterMs: 1500},
				}
				if intents[0].GetClass() != mtcpv1.KubeAuditIntent_WRITE || intents[0].GetName() != "web-0" {
					results[0] = &mtcpv1.KubeAuditResult{IntentId: intents[0].GetIntentId(), Refused: "invalid"}
				}
				_ = s.send(sharedmtcp.MessageKubeAuditAck, &mtcpv1.KubeAuditAck{BatchId: m.GetBatchId(), Results: results})
			case *mtcpv1.KubeAuditOutcomes:
				reported <- m
			}
		}
	})
	core.set(func(fake *fakeCore) { fake.extra = append(fake.extra, kubeAuditCapability) })
	trust := gatewayTrust(t, core)
	calls := make(chan controlplane.KubeAuditCall)
	reports := make(chan controlplane.KubeAuditReport)
	options := controlplane.NetmapOptions{
		Hostname: "meshgw-0", PinnedFingerprint: trust.Fingerprint,
		PeerProbePublicKey: "discokey:" + bytesHexOf(discoKey[:]), KubeAudits: calls, KubeAuditReports: reports,
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	mapped := make(chan networkmap.Snapshot, 4)
	done := make(chan error, 1)
	go func() {
		done <- core.gatewayClient().StreamNetmap(ctx, core.origin(), trust.Material, options,
			func(_ context.Context, snapshot networkmap.Snapshot) error {
				mapped <- snapshot
				return nil
			})
	}()
	select {
	case <-mapped:
	case <-time.After(5 * time.Second):
		t.Fatal("no map")
	}
	call := func(batch controlplane.KubeAuditBatch) chan controlplane.KubeAuditReply {
		t.Helper()
		reply := make(chan controlplane.KubeAuditReply, 1)
		select {
		case calls <- controlplane.KubeAuditCall{Batch: batch, Reply: reply, Deadline: time.Now().Add(10 * time.Second)}:
		case <-time.After(5 * time.Second):
			t.Fatal("the stream took no call")
		}
		return reply
	}
	var answer controlplane.KubeAuditReply
	select {
	case answer = <-call(testAuditBatch(1, 1, 2)):
	case <-time.After(10 * time.Second):
		t.Fatal("no answer")
	}
	if answer.Err != nil || len(answer.Results) != 2 || !answer.Results[0].Recorded() ||
		answer.Results[0].AuditID != [16]byte(bytes.Repeat([]byte{7}, 16)) || answer.Results[1].Refused != "limited" ||
		answer.Results[1].RetryAfter != 1500*time.Millisecond || answer.Results[1].IntentID != [16]byte{2} {
		t.Fatalf("answer = %+v", answer)
	}
	select {
	case reports <- controlplane.KubeAuditReport{
		Outcomes: []controlplane.KubeAuditOutcome{{AuditID: [16]byte{7}, Status: 200, Duration: 40 * time.Millisecond}},
		Denials:  []controlplane.KubeAuditDenials{{Reason: "forbidden", Count: 2, First: time.Now(), Last: time.Now()}},
	}:
	case <-time.After(5 * time.Second):
		t.Fatal("the stream took no report")
	}
	select {
	case got := <-reported:
		if len(got.GetOutcomes()) != 1 || got.GetOutcomes()[0].GetStatus() != 200 ||
			got.GetOutcomes()[0].GetDurationMs() != 40 || len(got.GetDenials()) != 1 {
			t.Fatalf("report = %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no report")
	}
	// A batch acked after its deadline is answered a timeout, and its
	// record reported as not forwarded.
	lateReply := make(chan controlplane.KubeAuditReply, 1)
	calls <- controlplane.KubeAuditCall{Batch: testAuditBatch(4, 5), Reply: lateReply,
		Deadline: time.Now().Add(100 * time.Millisecond)}
	if got := <-lateReply; !errors.Is(got.Err, controlplane.ErrKubeAuditTimeout) {
		t.Fatalf("late batch = %+v", got)
	}
	select {
	case got := <-reported:
		if len(got.GetOutcomes()) != 1 || got.GetOutcomes()[0].GetStatus() != 0 ||
			!bytes.Equal(got.GetOutcomes()[0].GetAuditId(), bytes.Repeat([]byte{8}, 16)) {
			t.Fatalf("late report = %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no report of the record never forwarded")
	}
	// The session ends while a batch waits.
	pending := call(testAuditBatch(3, 4))
	select {
	case <-waiting:
	case <-time.After(5 * time.Second):
		t.Fatal("the third batch was not sent")
	}
	cancel()
	select {
	case got := <-pending:
		if !errors.Is(got.Err, controlplane.ErrKubeAuditSessionLost) {
			t.Fatalf("answer = %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting batch was never answered")
	}
	<-done
	if !slices.ContainsFunc(core.hello, func(hello *mtcpv1.ClientHello) bool {
		return slices.Contains(hello.GetCapabilities(), kubeAuditCapability)
	}) {
		t.Fatal("gateway.audit1 not declared")
	}
}

// Calls the session cannot send are answered at once and never block; at
// most four batches wait; a deadline answers a batch Core never acks.
func TestGatewayOperationCallEdges(t *testing.T) {
	t.Parallel()
	offered := &session{reply: &mtcpv1.ServerHello{Capabilities: []string{kubeAuditCapability}}}
	run := &sessionRun{stream: &netmapStream{client: NewGateway()}, s: &session{reply: &mtcpv1.ServerHello{}}}
	answer := func(call controlplane.KubeAuditCall) controlplane.KubeAuditReply {
		t.Helper()
		reply := make(chan controlplane.KubeAuditReply, 1)
		call.Reply = reply
		if err := run.sendKubeAudit(call); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-reply:
			return got
		default:
			t.Fatal("no answer at once")
			return controlplane.KubeAuditReply{}
		}
	}
	if got := answer(controlplane.KubeAuditCall{Batch: testAuditBatch(1, 1)}); !errors.Is(got.Err,
		controlplane.ErrKubeAuditUnsupported) {
		t.Fatalf("without the capability: %+v", got)
	}
	run.s = offered
	stale := controlplane.KubeAuditCall{Batch: testAuditBatch(1, 1), Deadline: time.Now().Add(-time.Second)}
	if got := answer(stale); !errors.Is(got.Err, controlplane.ErrKubeAuditTimeout) {
		t.Fatalf("stale: %+v", got)
	}
	for name, batch := range map[string]controlplane.KubeAuditBatch{
		"empty": testAuditBatch(1), "too many": testAuditBatch(1, make([]byte, 129)...),
		"unknown class": func() controlplane.KubeAuditBatch {
			batch := testAuditBatch(1, 1)
			batch.Intents[0].Class = "read"
			return batch
		}(),
	} {
		if got := answer(controlplane.KubeAuditCall{Batch: batch}); !errors.Is(got.Err, controlplane.ErrKubeAuditBatch) {
			t.Fatalf("%s: %+v", name, got)
		}
	}
	// Over the message's size: never sent, the session kept (review b2 H1).
	large := testAuditBatch(1, make([]byte, 128)...)
	for index := range large.Intents {
		large.Intents[index].Name = string(bytes.Repeat([]byte{'n'}, 1100))
	}
	if got := answer(controlplane.KubeAuditCall{Batch: large}); !errors.Is(got.Err, controlplane.ErrKubeAuditBatch) {
		t.Fatalf("oversized: %+v", got)
	}
	// Four in flight: a fifth is busy, and so is a batch ID already waiting.
	run.kubeAudits = map[[16]byte]*kubeAuditInFlightCall{}
	waiting := make([]chan controlplane.KubeAuditReply, 4)
	for index := range waiting {
		waiting[index] = make(chan controlplane.KubeAuditReply, 1)
		run.kubeAudits[[16]byte{byte(10 + index)}] = &kubeAuditInFlightCall{intents: [][16]byte{{1}},
			reply: waiting[index], deadline: time.Now().Add(time.Hour)}
	}
	if got := answer(controlplane.KubeAuditCall{Batch: testAuditBatch(20, 1)}); !errors.Is(got.Err,
		controlplane.ErrKubeAuditBusy) {
		t.Fatalf("a fifth: %+v", got)
	}
	// The one past its deadline is answered and kept; the others wait on.
	run.kubeAudits[[16]byte{10}].deadline = time.Now().Add(-time.Second)
	run.timeOutKubeAudits()
	if _, kept := run.kubeAuditLate[[16]byte{10}]; !kept {
		t.Fatal("a timed-out batch was not kept for its late ack")
	}
	// A late ack recording nothing reports nothing.
	_ = run.kubeAuditAck(&mtcpv1.KubeAuditAck{BatchId: append([]byte{10}, make([]byte, 15)...),
		Results: []*mtcpv1.KubeAuditResult{{IntentId: append([]byte{1}, make([]byte, 15)...), Refused: "stale"}}})
	if _, kept := run.kubeAuditLate[[16]byte{10}]; kept {
		t.Fatal("a late ack did not end its batch")
	}
	if got := <-waiting[0]; !errors.Is(got.Err, controlplane.ErrKubeAuditTimeout) || len(run.kubeAudits) != 3 {
		t.Fatalf("timeout: %+v, %d waiting", got, len(run.kubeAudits))
	}
	if got := answer(controlplane.KubeAuditCall{Batch: testAuditBatch(11, 1)}); !errors.Is(got.Err,
		controlplane.ErrKubeAuditBusy) {
		t.Fatalf("a batch already waiting: %+v", got)
	}
	// An ack out of form answers its batch with ErrKubeAuditAck.
	_ = run.kubeAuditAck(&mtcpv1.KubeAuditAck{BatchId: append([]byte{11}, make([]byte, 15)...),
		Results: []*mtcpv1.KubeAuditResult{{IntentId: append([]byte{1}, make([]byte, 15)...)}}})
	if got := <-waiting[1]; !errors.Is(got.Err, controlplane.ErrKubeAuditAck) {
		t.Fatalf("an ack recorded without an audit_id: %+v", got)
	}
	run.endKubeAudits(controlplane.ErrKubeAuditSessionLost)
	for _, reply := range waiting[2:] {
		if got := <-reply; !errors.Is(got.Err, controlplane.ErrKubeAuditSessionLost) {
			t.Fatalf("end: %+v", got)
		}
	}
	// No answer channel, or a full one: nothing blocks.
	if err := run.sendKubeAudit(controlplane.KubeAuditCall{Batch: testAuditBatch(1, 1)}); err != nil {
		t.Fatal(err)
	}
	full := make(chan controlplane.KubeAuditReply, 1)
	full <- controlplane.KubeAuditReply{}
	run.kubeAudits[[16]byte{30}] = &kubeAuditInFlightCall{reply: full, deadline: time.Now()}
	run.endKubeAudits(controlplane.ErrKubeAuditSessionLost)
	// meshd never takes calls, and no gateway takes them before a map.
	if (&sessionRun{stream: &netmapStream{client: New()}, mapped: true}).kubeAuditCalls() != nil {
		t.Fatal("meshd takes operation calls")
	}
	if (&sessionRun{stream: &netmapStream{client: NewGateway()}}).kubeAuditReports() != nil {
		t.Fatal("a gateway takes reports before its map")
	}
}

func TestDecodeKubeAuditResults(t *testing.T) {
	t.Parallel()
	intents := [][16]byte{{1}, {2}}
	id := func(first byte) []byte { return append([]byte{first}, make([]byte, 15)...) }
	audit := bytes.Repeat([]byte{7}, 16)
	if got, ok := decodeKubeAuditResults(intents, []*mtcpv1.KubeAuditResult{
		{IntentId: id(1), AuditId: audit}, {IntentId: id(2), Refused: "stale", RetryAfterMs: 1 << 62},
	}); !ok || got[1].RetryAfter != time.Hour || got[1].Recorded() {
		t.Fatalf("results = %+v, %t", got, ok)
	}
	for name, results := range map[string][]*mtcpv1.KubeAuditResult{
		"too few":                {{IntentId: id(1), AuditId: audit}},
		"another intent":         {{IntentId: id(1), AuditId: audit}, {IntentId: id(3), Refused: "x"}},
		"recorded without an ID": {{IntentId: id(1)}, {IntentId: id(2), Refused: "x"}},
		"refused with an ID":     {{IntentId: id(1), AuditId: audit}, {IntentId: id(2), Refused: "x", AuditId: audit}},
		"short audit_id":         {{IntentId: id(1), AuditId: audit[:8]}, {IntentId: id(2), Refused: "x"}},
	} {
		if _, ok := decodeKubeAuditResults(intents, results); ok {
			t.Errorf("%s: taken", name)
		}
	}
}

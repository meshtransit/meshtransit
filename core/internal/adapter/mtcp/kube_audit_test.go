package mtcp

import (
	"context"
	"sync"
	"testing"
	"time"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/kubeaudit"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

const (
	auditPeer  = "01890f00-0000-7000-8000-000000000702"
	auditOther = "01890f00-0000-7000-8000-000000000703"
)

// fakeKubeAudit accepts every row, optionally only once released.
type fakeKubeAudit struct {
	mu      sync.Mutex
	rows    [][]kubeaudit.Row
	release chan struct{}
}

func (audit *fakeKubeAudit) Submit(rows []kubeaudit.Row) <-chan []kubeaudit.Answer {
	audit.mu.Lock()
	audit.rows = append(audit.rows, rows)
	release := audit.release
	audit.mu.Unlock()
	answers := make(chan []kubeaudit.Answer, 1)
	go func() {
		if release != nil {
			<-release
		}
		got := make([]kubeaudit.Answer, len(rows))
		for index := range got {
			got[index] = kubeaudit.Answer{Outcome: kubeaudit.OutcomeAccepted, AuditID: must(publicid.New())}
		}
		answers <- got
	}()
	return answers
}

func (audit *fakeKubeAudit) submitted() [][]kubeaudit.Row {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	return audit.rows
}

type fakeKubeAuditReports struct {
	mu      sync.Mutex
	reports []kubeaudit.Reports
	full    bool
}

func (reports *fakeKubeAuditReports) Submit(report kubeaudit.Reports) bool {
	reports.mu.Lock()
	defer reports.mu.Unlock()
	if reports.full {
		return false
	}
	reports.reports = append(reports.reports, report)
	return true
}

type fakeKubeAuditLimits struct{ wait time.Duration }

func (limits fakeKubeAuditLimits) Take(context.Context, string, string, int) (time.Duration, bool) {
	return limits.wait, limits.wait == 0
}

// kubeAuditFixture is a gateway session that negotiated gateway.audit1,
// holds its presence, and was sent a map granting auditPeer "view" and
// "edit" until an hour from now, Core having read it as standing at stood.
func kubeAuditFixture(t *testing.T, audit *fakeKubeAudit, stood time.Time) *conversationFixture {
	t.Helper()
	f := gatewayFixture(t, &fakeMachineKeyRotations{})
	// Intent IDs and the map's freshness are checked on Core's clock.
	f.clockMu.Lock()
	f.clock = time.Now()
	f.clockMu.Unlock()
	f.session.capabilities = append(f.session.capabilities, CapabilityKubeAudit)
	f.talk.application.options.KubeAudit = audit
	f.talk.application.options.KubeAuditReports = &fakeKubeAuditReports{}
	f.run()
	f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
	if _, claimed := f.talk.awaitClaim(t.Context()); !claimed {
		t.Fatal("the stream never claimed the presence")
	}
	scope := snapshotFixture(t, 7).Scope()
	granted := peerFixture(t, scope, auditPeer, 702, "100.64.0.2", 2)
	other := peerFixture(t, scope, auditOther, 703, "100.64.0.3", 3)
	until := time.Now().Add(time.Hour)
	view := must(mapsession.NewKubernetesView(map[node.ID]mapsession.KubernetesAccess{granted.NodeID(): {
		Grants:    []mapsession.KubernetesGrant{{Group: "edit", ValidUntil: until}, {Group: "view", ValidUntil: until}},
		OwnerKind: mapsession.KubernetesOwnerMember, OwnerRef: "01890f00-0000-7000-8000-000000000011",
	}}))
	if !stood.IsZero() {
		sink := f.talk.sink
		sink.mu.Lock()
		sink.current, sink.hasCurrent = snapshotFixture(t, 7, granted, other).WithKubernetes(view), true
		sink.authorityFresh, sink.authorityStood, sink.stoodRevision = true, stood, 7
		sink.mu.Unlock()
	}
	return f
}

func auditIntent(id byte, peer string, groups ...string) *mtcpv1.KubeAuditIntent {
	now := time.Now()
	intentID := make([]byte, 16)
	millis := uint64(now.UnixMilli())
	for index := range 6 {
		intentID[5-index] = byte(millis >> (8 * index))
	}
	intentID[6], intentID[8], intentID[15] = 0x70, 0x80, id
	return &mtcpv1.KubeAuditIntent{IntentId: intentID, PeerDeviceId: peer, Groups: groups,
		Class: mtcpv1.KubeAuditIntent_EXEC, Verb: "create", Resource: "pods", Subresource: "exec",
		Namespace: "default", Name: "web-0", ObservedMs: now.UnixMilli()}
}

func (f *conversationFixture) askKubeAudit(intents ...*mtcpv1.KubeAuditIntent) *mtcpv1.KubeAuditAck {
	f.t.Helper()
	f.sendKubeAudit(repeat(5, 16), intents...)
	return f.expectPast(sharedmtcp.MessageKubeAuditAck).(*mtcpv1.KubeAuditAck)
}

func (f *conversationFixture) sendKubeAudit(batch []byte, intents ...*mtcpv1.KubeAuditIntent) {
	f.t.Helper()
	if err := f.talk.Receive(f.t.Context(), sharedmtcp.MessageKubeAuditIntents,
		&mtcpv1.KubeAuditIntents{BatchId: batch, Intents: intents}); err != nil {
		f.t.Fatalf("Receive() = %v, want the session kept", err)
	}
}

func refusals(ack *mtcpv1.KubeAuditAck) []string {
	got := make([]string, len(ack.GetResults()))
	for index, result := range ack.GetResults() {
		got[index] = result.GetRefused()
	}
	return got
}

// Each intent is answered in order: recorded with an audit_id, or refused
// for its own reason; only the recorded reach the writer, with the owner
// and revision of the map Core sent (K1b0 §3.3).
func TestKubeAuditAnswersEachIntent(t *testing.T) {
	t.Parallel()
	audit := &fakeKubeAudit{}
	f := kubeAuditFixture(t, audit, time.Now())
	badClass := auditIntent(2, auditPeer, "view")
	badClass.Class = mtcpv1.KubeAuditIntent_CLASS_UNSPECIFIED
	ack := f.askKubeAudit(auditIntent(1, auditPeer, "view", "edit"), badClass, auditIntent(1, auditPeer, "view"),
		auditIntent(3, auditOther, "view"), auditIntent(4, auditPeer, "admin"), auditIntent(5, "not-an-id"))
	want := []string{"", "invalid", "invalid", "device", "not_granted", "invalid"}
	if got := refusals(ack); len(got) != len(want) || got[0] != "" || len(ack.GetResults()[0].GetAuditId()) != 16 {
		t.Fatalf("results %v", ack.GetResults())
	}
	for index, reason := range refusals(ack) {
		if reason != want[index] {
			t.Fatalf("intent %d refused %q, want %q", index, reason, want[index])
		}
	}
	if string(ack.GetBatchId()) != string(repeat(5, 16)) || ack.GetResults()[3].GetRetryAfterMs() != 0 {
		t.Fatalf("ack %v", ack)
	}
	submitted := audit.submitted()
	if len(submitted) != 1 || len(submitted[0]) != 1 {
		t.Fatalf("submitted %v", submitted)
	}
	row := submitted[0][0]
	if row.Owner.Kind != "member" || row.NetworkRevision != 7 || row.Intent.Peer.String() != auditPeer ||
		row.Gateway.Workspace != "01890f00-0000-7000-8000-000000000101" || row.Gateway.NodeKey == ([32]byte{}) ||
		row.ClockSkew {
		t.Fatalf("row %+v", row)
	}
}

// A batch the session cannot have recorded is refused whole, with a wait
// when it may be sent again, and never reaches the writer.
func TestKubeAuditRefusesBatches(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		stood  time.Time
		change func(*conversationFixture)
		batch  []byte
		want   string
		retry  bool
	}{
		"bad batch ID": {stood: time.Now(), batch: repeat(5, 8), want: "invalid"},
		"no map":       {want: "stale", retry: true},
		"stale map":    {stood: time.Now().Add(-kubeAuditStaleAfter - time.Second), want: "stale", retry: true},
		"over budget": {stood: time.Now(), want: "limited", retry: true,
			change: func(f *conversationFixture) { f.session.auditOver = true }},
		"limited": {stood: time.Now(), want: "limited", retry: true, change: func(f *conversationFixture) {
			f.talk.application.options.KubeAuditLimits = fakeKubeAuditLimits{wait: 3 * time.Second}
		}},
		"no presence": {stood: time.Now(), want: "unavailable", retry: true, change: func(f *conversationFixture) {
			f.talk.endClaim()
		}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			audit := &fakeKubeAudit{}
			f := kubeAuditFixture(t, audit, test.stood)
			if test.change != nil {
				test.change(f)
			}
			batch := test.batch
			if batch == nil {
				batch = repeat(5, 16)
			}
			f.sendKubeAudit(batch, auditIntent(1, auditPeer, "view"), auditIntent(2, auditPeer, "edit"))
			ack := f.expectPast(sharedmtcp.MessageKubeAuditAck).(*mtcpv1.KubeAuditAck)
			for _, result := range ack.GetResults() {
				if result.GetRefused() != test.want || (result.GetRetryAfterMs() > 0) != test.retry ||
					len(result.GetAuditId()) != 0 {
					t.Fatalf("results %v", ack.GetResults())
				}
			}
			if len(ack.GetResults()) != 2 || len(audit.submitted()) != 0 {
				t.Fatalf("%d results, %d submissions", len(ack.GetResults()), len(audit.submitted()))
			}
		})
	}
}

// At most four batches of a session wait for their ack; a fifth is
// limited at once (K1b0 §3.3).
func TestKubeAuditBoundsBatchesInFlight(t *testing.T) {
	t.Parallel()
	audit := &fakeKubeAudit{release: make(chan struct{})}
	f := kubeAuditFixture(t, audit, time.Now())
	for id := range byte(kubeAuditInFlight) {
		f.sendKubeAudit(repeat(id+1, 16), auditIntent(id+1, auditPeer, "view"))
	}
	ack := f.askKubeAudit(auditIntent(9, auditPeer, "view"))
	if got := refusals(ack); len(got) != 1 || got[0] != "limited" || string(ack.GetBatchId()) != string(repeat(5, 16)) {
		t.Fatalf("the fifth batch: %v", ack)
	}
	close(audit.release)
	for range kubeAuditInFlight {
		if got := refusals(f.expectPast(sharedmtcp.MessageKubeAuditAck).(*mtcpv1.KubeAuditAck)); got[0] != "" {
			t.Fatalf("a waiting batch: %v", got)
		}
	}
	if accepted := refusals(f.askKubeAudit(auditIntent(10, auditPeer, "view"))); accepted[0] != "" {
		t.Fatalf("after the acks: %v", accepted)
	}
}

// Without gateway.audit1 the session gets an Error and stays.
func TestKubeAuditOutsideTheCapability(t *testing.T) {
	t.Parallel()
	f := gatewayFixture(t, &fakeMachineKeyRotations{})
	f.talk.application.options.KubeAudit = &fakeKubeAudit{}
	f.talk.application.options.KubeAuditReports = &fakeKubeAuditReports{}
	f.run()
	f.expectStream(node.Key(f.session.Hello().GetNodeKey()))
	f.sendKubeAudit(repeat(5, 16), auditIntent(1, auditPeer, "view"))
	if got := f.expectPast(sharedmtcp.MessageError).(*mtcpv1.Error); got.GetCode() != mtcpv1.Error_UNSUPPORTED ||
		got.GetFatal() {
		t.Fatalf("error %v", got)
	}
}

// Outcomes and denials in form are queued under the gateway; the rest are
// dropped; nothing answers them.
func TestKubeAuditOutcomes(t *testing.T) {
	t.Parallel()
	f := kubeAuditFixture(t, &fakeKubeAudit{}, time.Now())
	reports := &fakeKubeAuditReports{}
	f.talk.application.options.KubeAuditReports = reports
	auditID := must(publicid.New())
	now := time.Now().UnixMilli()
	message := &mtcpv1.KubeAuditOutcomes{
		Outcomes: []*mtcpv1.KubeAuditOutcome{
			{AuditId: auditID[:], Status: 201, DurationMs: 40},
			{AuditId: auditID[:8], Status: 201},
			{AuditId: auditID[:], Status: 1000},
		},
		Denials: []*mtcpv1.KubeAuditDenials{
			{PeerDeviceId: auditPeer, Reason: "forbidden", Count: 3, FirstMs: now - 1000, LastMs: now},
			{Reason: "stale", Count: 1, FirstMs: now, LastMs: now},
			{Reason: "bored", Count: 1, FirstMs: now, LastMs: now},
			{Reason: "other", Count: 0, FirstMs: now, LastMs: now},
			{Reason: "other", Count: 1, FirstMs: now, LastMs: now - 1},
		},
	}
	if err := f.talk.Receive(t.Context(), sharedmtcp.MessageKubeAuditOutcomes, message); err != nil {
		t.Fatal(err)
	}
	reports.mu.Lock()
	defer reports.mu.Unlock()
	if len(reports.reports) != 1 {
		t.Fatalf("%d reports", len(reports.reports))
	}
	got := reports.reports[0]
	if len(got.Finished) != 1 || got.Finished[0].AuditID != auditID || got.Finished[0].Duration != 40*time.Millisecond ||
		len(got.Denials) != 2 || got.Denials[0].Peer.String() != auditPeer || got.Denials[1].Peer.IsValid() ||
		got.Gateway.NodeKey == ([32]byte{}) {
		t.Fatalf("report %+v", got)
	}
}

// Sending the same map again keeps when Core last read it as standing
// (review b0b3 M1), but never makes a paused authority current (L3).
func TestKubeAuditMapAcrossResyncs(t *testing.T) {
	t.Parallel()
	f := kubeAuditFixture(t, &fakeKubeAudit{}, time.Now())
	stood := time.Now().Add(time.Hour)
	f.talk.sink.mu.Lock()
	f.talk.sink.authorityStood = stood
	f.talk.sink.mu.Unlock()
	if err := f.talk.sink.resync(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if _, got, ok := f.talk.sink.kubeAuditMap(); !ok || !got.Equal(stood) {
		t.Fatalf("after a resync: stood %v, %v", got, ok)
	}
	if got := refusals(f.askKubeAudit(auditIntent(1, auditPeer, "view"))); got[0] != "" {
		t.Fatalf("after a resync: %v", got)
	}
	f.talk.sink.revokeFreshness()
	if err := f.talk.sink.resync(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if got := refusals(f.askKubeAudit(auditIntent(2, auditPeer, "view"))); got[0] != "stale" {
		t.Fatalf("a paused authority sent again: %v", got)
	}
}

// A batch past its bound is answered within the ack's size, the session
// kept (review b0b3 M2).
func TestKubeAuditBoundsTheAck(t *testing.T) {
	t.Parallel()
	f := kubeAuditFixture(t, &fakeKubeAudit{}, time.Now())
	intents := make([]*mtcpv1.KubeAuditIntent, 1200)
	for index := range intents {
		intents[index] = auditIntent(byte(index), auditPeer, "view")
	}
	ack := f.askKubeAudit(intents...)
	if got := refusals(ack); len(got) != kubeaudit.MaximumIntents || got[0] != "invalid" {
		t.Fatalf("%d results, first %q", len(got), got[0])
	}
}

// A session ending while a batch waits stops waiting: its work is joined,
// the counter released, and no ack sent (review b0b3 M3).
func TestKubeAuditWorkEndsWithTheConversation(t *testing.T) {
	t.Parallel()
	audit := &fakeKubeAudit{release: make(chan struct{})}
	defer close(audit.release)
	f := kubeAuditFixture(t, audit, time.Now())
	f.sendKubeAudit(repeat(5, 16), auditIntent(1, auditPeer, "view"))
	f.talk.closeKubeAudits()
	if pending := f.talk.kubeAuditPending.Load(); pending != 0 {
		t.Fatalf("%d batches still counted", pending)
	}
	if _, working := f.talk.startKubeAudit(t.Context()); working {
		t.Fatal("work started after the conversation ended")
	}
	for {
		kind, _, ok := f.node.read()
		if !ok {
			break
		}
		if kind == sharedmtcp.MessageKubeAuditAck {
			t.Fatal("an ack was sent after the conversation ended")
		}
	}
}

// A session that serves no gateway has nothing recorded; an observed time
// far from Core's is marked.
func TestKubeAuditGatewayAndSkew(t *testing.T) {
	t.Parallel()
	f := kubeAuditFixture(t, &fakeKubeAudit{}, time.Now())
	f.session.gate.Gateway = false
	if got := refusals(f.askKubeAudit(auditIntent(1, auditPeer, "view"))); got[0] != "unavailable" {
		t.Fatalf("no gateway: %v", got)
	}
	audit := &fakeKubeAudit{}
	g := kubeAuditFixture(t, audit, time.Now())
	skewed := auditIntent(2, auditPeer, "view")
	skewed.ObservedMs -= time.Minute.Milliseconds()
	if got := refusals(g.askKubeAudit(skewed)); got[0] != "" {
		t.Fatalf("skewed: %v", got)
	}
	if rows := audit.submitted(); len(rows) != 1 || !rows[0][0].ClockSkew {
		t.Fatal("a skewed observed time was not marked")
	}
}

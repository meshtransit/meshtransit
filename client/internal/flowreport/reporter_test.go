package flowreport

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/flowcount"
	"meshtransit.net/client/internal/packetmeta"
	"meshtransit.net/shared/flowlog"
	"meshtransit.net/shared/key"
)

const testAudience = "meshflow:test"

// fakeReceiver applies flowlog-v1 §4–5 with an in-memory state.
type fakeReceiver struct {
	mu        sync.Mutex
	receiver  *flowlog.Receiver
	now       time.Time
	held      map[string]uint64
	committed map[string]uint64
	records   int
	batches   []uint64
	// commit commits what is held at once; plain answers with this status;
	// status answers sealed with it.
	commit bool
	plain  int
	status flowlogv1.FlowBatchResponse_Status
	forget bool
	// change alters the answer before it is sealed.
	change func(*flowlogv1.FlowBatchResponse)
}

func (f *fakeReceiver) post(_ context.Context, header string, body []byte) (controlplane.FlowPostResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.plain != 0 {
		return controlplane.FlowPostResult{Status: f.plain}, nil
	}
	token, err := f.receiver.CheckToken(header, f.now)
	if err != nil {
		return controlplane.FlowPostResult{Status: flowlog.Status(err)}, nil
	}
	incoming, err := f.receiver.ReadHandshake(token, bytes.NewReader(body))
	if err != nil {
		return controlplane.FlowPostResult{Status: flowlog.Status(err)}, nil
	}
	request := incoming.Request
	boot := string(request.GetBootId())
	if f.forget {
		delete(f.held, boot)
		f.forget = false
	}
	held, known := f.held[boot]
	if !known {
		held = request.GetHeldFrom() - 1
		f.committed[boot] = held
	}
	if request.GetHeldFrom() > held+1 {
		held = request.GetHeldFrom() - 1 // rule 1: a lost event
	}
	answer := &flowlogv1.FlowBatchResponse{Status: flowlogv1.FlowBatchResponse_ACCEPTED}
	switch sequence := request.GetSequence(); {
	case f.status != 0:
		answer.Status = f.status
	case sequence <= held:
	case sequence == held+1:
		batch, err := incoming.ReadBatch()
		if err != nil {
			return controlplane.FlowPostResult{Status: flowlog.Status(err)}, nil
		}
		f.records += len(batch.GetRecords())
		f.batches = append(f.batches, sequence)
		held = sequence
	default:
		answer.Status, answer.NextSequence = flowlogv1.FlowBatchResponse_OUT_OF_ORDER, held+1
	}
	f.held[boot] = held
	if f.commit {
		f.committed[boot] = held
	}
	answer.CommittedSequence = f.committed[boot]
	if f.change != nil {
		f.change(answer)
	}
	sealed, err := incoming.Answer(answer)
	if err != nil {
		return controlplane.FlowPostResult{}, err
	}
	return controlplane.FlowPostResult{Status: http.StatusOK, Body: sealed}, nil
}

type reporterFixture struct {
	reporter *Reporter
	receiver *fakeReceiver
	ticket   controlplane.FlowTicket
	counter  *flowcount.Counter
	now      time.Time
}

func newReporterFixture(t *testing.T, roles ...flowlogv1.FlowTokenClaims_Role) *reporterFixture {
	t.Helper()
	now := time.UnixMilli(1_800_000_000_000)
	machine, _ := key.NewMachinePrivate(nil)
	receiverKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	public, signing, _ := ed25519.GenerateKey(nil)
	if len(roles) == 0 {
		roles = []flowlogv1.FlowTokenClaims_Role{flowlogv1.FlowTokenClaims_DEVICE}
	}
	machinePublic := machine.Public()
	claims := &flowlogv1.FlowTokenClaims{
		Version: 1, Kid: "k1", Audience: testAudience, WorkspaceId: make([]byte, 16),
		NetworkId: bytes.Repeat([]byte{2}, 16), DeviceId: bytes.Repeat([]byte{3}, 16), MachineKey: machinePublic[:],
		Roles: roles, IssuedAtMs: now.UnixMilli(), NotBeforeMs: now.UnixMilli(),
		ExpiresAtMs: now.Add(15 * time.Minute).UnixMilli(), TokenId: bytes.Repeat([]byte{4}, 16), WindowS: 60,
	}
	for _, role := range roles {
		if role == flowlogv1.FlowTokenClaims_ROUTER {
			claims.SiteIds = [][]byte{bytes.Repeat([]byte{5}, 16)}
		}
	}
	token, err := flowlog.SignToken(claims, signing)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &reporterFixture{now: now}
	fixture.receiver = &fakeReceiver{
		receiver: &flowlog.Receiver{
			Key: receiverKey, SigningKeys: map[string]ed25519.PublicKey{"k1": public},
			Audience: testAudience,
		},
		now: now, held: map[string]uint64{}, committed: map[string]uint64{}, commit: true,
	}
	fixture.ticket = controlplane.FlowTicket{
		Token: token, ReceiverKey: receiverKey.PublicKey().Bytes(), NotAfter: now.Add(10 * time.Minute),
		Machine: machine, Post: fixture.receiver.post,
	}
	fixture.reporter = New(Config{
		Dir: filepath.Join(t.TempDir(), "flowlog"), SetCounter: func(counter *flowcount.Counter) { fixture.counter = counter },
		Policy: func() Policy { return testPolicy }, Now: func() time.Time { return fixture.now },
	})
	return fixture
}

func (f *reporterFixture) traffic(port uint16) {
	f.counter.Observe(flowcount.Observation{
		Header: packetmeta.Header{
			Source: netip.MustParseAddr("100.64.0.1"), Destination: netip.MustParseAddr("100.64.0.2"),
			Protocol: packetmeta.ProtocolTCP, SourcePort: 40000, DestinationPort: port, TCPFlags: 0x02, Length: 60,
		},
		Class: flowcount.ClassMesh, Direction: flowcount.DirectionOutbound,
	}, f.now)
}

func (f *reporterFixture) window(current *active, ports ...uint16) {
	for _, port := range ports {
		f.traffic(port)
	}
	f.now = f.now.Add(time.Minute)
	f.reporter.tick(current)
}

// Counted traffic reaches the receiver and leaves the spool once committed.
func TestReporterSendsAndCommits(t *testing.T) {
	t.Parallel()
	fixture := newReporterFixture(t)
	current := fixture.reporter.apply(nil, fixture.ticket)
	if current == nil || fixture.counter == nil || fixture.counter.CountsForwarded() {
		t.Fatal("a device ticket did not start counting its own traffic only")
	}
	fixture.window(current, 22, 443)
	fixture.window(current, 80)
	fixture.reporter.sendTurn(t.Context(), current)
	if fixture.receiver.records != 3 || len(fixture.receiver.batches) != 2 {
		t.Fatalf("receiver got %d records in %v", fixture.receiver.records, fixture.receiver.batches)
	}
	if _, ok, _ := current.spool.Oldest(); ok {
		t.Fatal("committed batches stayed")
	}
	status := fixture.reporter.Status()
	if !status.On || status.LastError != "" || status.LastSent.IsZero() {
		t.Fatalf("status %+v", status)
	}
}

// Held but not committed batches stay; an idle resend learns the commit.
func TestReporterIdleResendLearnsCommit(t *testing.T) {
	t.Parallel()
	fixture := newReporterFixture(t)
	fixture.receiver.commit = false
	current := fixture.reporter.apply(nil, fixture.ticket)
	fixture.window(current, 22)
	fixture.reporter.sendTurn(t.Context(), current)
	if _, ok, _ := current.spool.Oldest(); !ok {
		t.Fatal("a held, uncommitted batch was dropped")
	}
	fixture.receiver.commit = true
	if wait := fixture.reporter.sendTurn(t.Context(), current); wait == 0 {
		t.Fatal("resent at once instead of after a window")
	}
	fixture.now = fixture.now.Add(2 * time.Minute)
	fixture.reporter.sendTurn(t.Context(), current)
	if _, ok, _ := current.spool.Oldest(); ok {
		t.Fatal("the idle resend did not learn the commit")
	}
	if len(fixture.receiver.batches) != 1 {
		t.Fatalf("the batch was written twice: %v", fixture.receiver.batches)
	}
}

// A plain HTTP error drops nothing and backs off; 401 waits for a ticket.
func TestReporterPlainErrors(t *testing.T) {
	t.Parallel()
	fixture := newReporterFixture(t)
	current := fixture.reporter.apply(nil, fixture.ticket)
	fixture.window(current, 22)
	fixture.receiver.plain = http.StatusServiceUnavailable
	if wait := fixture.reporter.sendTurn(t.Context(), current); wait < minBackoff {
		t.Fatalf("backoff %v", wait)
	}
	if _, ok, _ := current.spool.Oldest(); !ok || fixture.reporter.Status().LastError == "" {
		t.Fatal("a 503 dropped the batch or went unreported")
	}
	// Another replica writes the Network: keep the batch, back off, send
	// again with the same token.
	fixture.receiver.plain = http.StatusMisdirectedRequest
	fixture.now = fixture.now.Add(time.Minute)
	if wait := fixture.reporter.sendTurn(t.Context(), current); wait < minBackoff {
		t.Fatalf("421 backoff %v", wait)
	}
	if _, ok, _ := current.spool.Oldest(); !ok || current.tokenRefused {
		t.Fatal("a 421 dropped the batch or refused the token")
	}
	fixture.receiver.plain = http.StatusUnauthorized
	fixture.now = fixture.now.Add(time.Minute) // past the backoff, within the token
	fixture.reporter.sendTurn(t.Context(), current)
	if !current.tokenRefused {
		t.Fatal("a 401 did not wait for a new ticket")
	}
	fixture.receiver.plain = 0
	fixture.reporter.sendTurn(t.Context(), current)
	if len(fixture.receiver.batches) != 0 {
		t.Fatal("sent with a refused token")
	}
	current = fixture.reporter.apply(current, fixture.ticket)
	current.retryAt = time.Time{}
	fixture.receiver.now = fixture.now
	fixture.reporter.sendTurn(t.Context(), current)
	if len(fixture.receiver.batches) != 1 {
		t.Fatalf("a new ticket did not resume sending: %v", fixture.receiver.batches)
	}
}

// OUT_OF_ORDER sends the batch the receiver asks for; DISABLED drops the
// spool and starts a new boot.
func TestReporterOutOfOrderAndDisabled(t *testing.T) {
	t.Parallel()
	fixture := newReporterFixture(t)
	fixture.receiver.commit = false
	current := fixture.reporter.apply(nil, fixture.ticket)
	fixture.window(current, 22)
	fixture.window(current, 23)
	fixture.reporter.sendTurn(t.Context(), current)
	// The receiver loses its state and restarts at held_from: it asks for 1.
	fixture.receiver.forget = true
	fixture.window(current, 24)
	fixture.reporter.sendTurn(t.Context(), current)
	// 3 is out of order for a receiver starting again at held_from 1: the
	// node sends 1 and 2 again (same record IDs), then 3.
	if got := fixture.receiver.batches; !slices.Equal(got, []uint64{1, 2, 1, 2, 3}) {
		t.Fatalf("batches %v", got)
	}
	fixture.receiver.status = flowlogv1.FlowBatchResponse_DISABLED
	fixture.now = fixture.now.Add(2 * time.Minute)
	fixture.reporter.sendTurn(t.Context(), current)
	if _, ok, _ := current.spool.Oldest(); ok || current.spool.Highest() != 0 {
		t.Fatal("DISABLED kept the spool")
	}
}

// A forwarding role counts forwarded traffic; an empty ticket stops it all.
func TestReporterRolesAndOff(t *testing.T) {
	t.Parallel()
	fixture := newReporterFixture(t, flowlogv1.FlowTokenClaims_DEVICE, flowlogv1.FlowTokenClaims_ROUTER)
	current := fixture.reporter.apply(nil, fixture.ticket)
	if !fixture.counter.CountsForwarded() {
		t.Fatal("a router's ticket did not count forwarded traffic")
	}
	if current = fixture.reporter.apply(current, controlplane.FlowTicket{}); current != nil || fixture.counter != nil ||
		fixture.reporter.Status().On {
		t.Fatal("an empty ticket did not stop logging")
	}
}

// Run takes tickets and stops with its context.
func TestReporterRun(t *testing.T) {
	t.Parallel()
	fixture := newReporterFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- fixture.reporter.Run(ctx) }()
	fixture.reporter.SetTicket(fixture.ticket)
	deadline := time.Now().Add(5 * time.Second)
	for !fixture.reporter.Status().On && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !fixture.reporter.Status().On {
		t.Fatal("a ticket did not turn logging on")
	}
	cancel()
	if err := <-done; err != nil || fixture.reporter.Status().On {
		t.Fatalf("run %v, status %+v after stopping", err, fixture.reporter.Status())
	}
}

// THROTTLED and retry_after_ms hold sending back across a window.
func TestReporterThrottleHolds(t *testing.T) {
	t.Parallel()
	fixture := newReporterFixture(t)
	current := fixture.reporter.apply(nil, fixture.ticket)
	fixture.window(current, 22)
	fixture.receiver.status = flowlogv1.FlowBatchResponse_THROTTLED
	fixture.receiver.change = func(answer *flowlogv1.FlowBatchResponse) { answer.RetryAfterMs = 90_000 }
	fixture.reporter.sendTurn(t.Context(), current)
	fixture.receiver.status, fixture.receiver.change = 0, nil
	fixture.window(current, 23) // a window passes: still within the 90 s
	if wait := fixture.reporter.sendTurn(t.Context(), current); wait <= 0 || len(fixture.receiver.batches) != 0 {
		t.Fatalf("sent while throttled: wait %v, batches %v", wait, fixture.receiver.batches)
	}
	fixture.now = fixture.now.Add(time.Minute)
	fixture.reporter.sendTurn(t.Context(), current)
	if len(fixture.receiver.batches) != 2 {
		t.Fatalf("after the throttle: %v", fixture.receiver.batches)
	}
}

// An answer committing past what was sent, or asking out of order for the
// batch just sent or a later one, drops nothing and backs off.
func TestReporterRefusesWrongAnswers(t *testing.T) {
	t.Parallel()
	for name, change := range map[string]func(*flowlogv1.FlowBatchResponse){
		"committed past sent": func(answer *flowlogv1.FlowBatchResponse) { answer.CommittedSequence = 2 },
		"out of order for itself": func(answer *flowlogv1.FlowBatchResponse) {
			answer.Status, answer.NextSequence, answer.CommittedSequence = flowlogv1.FlowBatchResponse_OUT_OF_ORDER, 1, 0
		},
	} {
		fixture := newReporterFixture(t)
		fixture.receiver.commit = false
		current := fixture.reporter.apply(nil, fixture.ticket)
		fixture.window(current, 22)
		fixture.window(current, 23)
		current.spool.mu.Lock()
		current.spool.entries = current.spool.entries[:1] // only batch 1 is sendable
		current.spool.mu.Unlock()
		fixture.receiver.change = change
		if wait := fixture.reporter.sendTurn(t.Context(), current); wait < minBackoff {
			t.Errorf("%s: no backoff (%v)", name, wait)
		}
		if current.spool.Len() != 1 || fixture.reporter.Status().LastError == "" {
			t.Errorf("%s: dropped or unreported", name)
		}
	}
}

// Past its token's expiry with no new ticket the node stops counting; a new
// ticket starts it again.
func TestReporterStopsCountingAfterExpiry(t *testing.T) {
	t.Parallel()
	fixture := newReporterFixture(t)
	current := fixture.reporter.apply(nil, fixture.ticket)
	fixture.now = fixture.now.Add(20 * time.Minute)
	fixture.reporter.tick(current)
	if fixture.counter != nil || fixture.reporter.Status().On {
		t.Fatal("still counting past the token's expiry")
	}
	if again := fixture.reporter.apply(current, fixture.ticket); again != current || fixture.counter == nil ||
		!fixture.reporter.Status().On {
		t.Fatal("a new ticket did not start counting again")
	}
}

// A ticket granting a forwarding role rebuilds the counter with its caps,
// keeping the old window.
func TestReporterRoleChange(t *testing.T) {
	t.Parallel()
	device := newReporterFixture(t)
	router := newReporterFixture(t, flowlogv1.FlowTokenClaims_DEVICE, flowlogv1.FlowTokenClaims_ROUTER)
	router.reporter, router.receiver = device.reporter, device.receiver
	// Both tickets for the same machine and Network: sign the router's
	// with the device fixture's key material.
	current := device.reporter.apply(nil, device.ticket)
	first := device.counter
	device.traffic(22)
	ticket := device.ticket
	claims, _ := flowlog.ReadClaims(router.ticket.Token)
	if len(claims.GetRoles()) != 2 {
		t.Fatal("router claims")
	}
	current.forwarder = false
	current.counter.CountForwarded(false)
	ticket.Token = router.ticket.Token
	ticket.Machine, ticket.ReceiverKey, ticket.Post = router.ticket.Machine, router.ticket.ReceiverKey, router.ticket.Post
	current = device.reporter.apply(current, ticket)
	if device.counter == first || !device.counter.CountsForwarded() || current.spool.Len() != 1 {
		t.Fatalf("role change: same counter %t, forwarded %t, kept %d", device.counter == first,
			device.counter.CountsForwarded(), current.spool.Len())
	}
}

// Run puts the last window on disk when it stops.
func TestReporterRunKeepsLastWindow(t *testing.T) {
	t.Parallel()
	fixture := newReporterFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	var counter *flowcount.Counter
	var mu sync.Mutex
	fixture.reporter.config.SetCounter = func(next *flowcount.Counter) {
		mu.Lock()
		counter = next
		mu.Unlock()
	}
	fixture.receiver.plain = http.StatusServiceUnavailable
	go func() { done <- fixture.reporter.Run(ctx) }()
	fixture.reporter.SetTicket(fixture.ticket)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		ready := counter != nil
		mu.Unlock()
		if ready {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	fixture.counter = counter
	mu.Unlock()
	fixture.traffic(22)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	dir := hex.EncodeToString(bytes.Repeat([]byte{2}, 16)) + "-" + hex.EncodeToString(bytes.Repeat([]byte{3}, 16))
	spool, err := OpenSpool(filepath.Join(fixture.reporter.config.Dir, dir), DiskLimits(), fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = spool.Close() }()
	if spool.Len() != 1 {
		t.Fatalf("the last window was not kept: %d batches", spool.Len())
	}
}

// After a restart the node still takes an answer committing what it sent
// before: the highest sequence sent is kept on disk.
func TestReporterCommitAfterRestart(t *testing.T) {
	t.Parallel()
	fixture := newReporterFixture(t)
	fixture.receiver.commit = false
	current := fixture.reporter.apply(nil, fixture.ticket)
	fixture.window(current, 22)
	fixture.window(current, 23)
	fixture.reporter.sendTurn(t.Context(), current)
	if len(fixture.receiver.batches) != 2 || current.spool.Len() != 2 {
		t.Fatalf("before the restart: %v, %d held", fixture.receiver.batches, current.spool.Len())
	}
	fixture.reporter.stop(current)
	fixture.receiver.commit = true
	restarted := fixture.reporter.apply(nil, fixture.ticket)
	fixture.reporter.sendTurn(t.Context(), restarted)
	if restarted.spool.Len() != 0 || fixture.reporter.Status().LastError != "" {
		t.Fatalf("after the restart: %d held, error %q", restarted.spool.Len(), fixture.reporter.Status().LastError)
	}
}

package mtcp

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/shared/key"
	sharedmtcp "meshtransit.net/shared/mtcp"
)

// deadlineTransport records the deadline of every record and, once failAfter
// records went out, fails the rest as a stalled reader would.
type deadlineTransport struct {
	mu        sync.Mutex
	deadlines []time.Time
	failAfter int
	closed    bool
	// now, when set, fails a record whose deadline has passed, as a
	// transport with write deadlines does.
	now func() time.Time
}

func (d *deadlineTransport) ReadRecord(time.Time) (sharedmtcp.RecordType, []byte, error) { select {} }

func (d *deadlineTransport) WriteRecord(_ sharedmtcp.RecordType, _ []byte, deadline time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.deadlines = append(d.deadlines, deadline)
	if d.now != nil && !deadline.After(d.now()) {
		return os.ErrDeadlineExceeded
	}
	if d.failAfter >= 0 && len(d.deadlines) > d.failAfter {
		return os.ErrDeadlineExceeded
	}
	return nil
}

func (d *deadlineTransport) Close() error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()
	return nil
}

func deadlineSession(t *testing.T, now func() time.Time, transport *deadlineTransport) (*Session, *Metrics) {
	t.Helper()
	control, _ := key.NewControlPrivate(nil)
	machine, _ := key.NewMachinePrivate(nil)
	client, init, err := sharedmtcp.StartClient(sharedmtcp.ClientConfig{Machine: machine, Control: control.Public(),
		Hello: &mtcpv1.ClientHello{ProtocolVersion: 1, TimestampMs: time.Now().UnixMilli(), NodeKey: bytes.Repeat([]byte{7}, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	server, _ := sharedmtcp.ReadInit(control, init, nil)
	reply := &mtcpv1.ServerHello{ProtocolVersion: 1, SessionId: make([]byte, 16)}
	coreNoise, response, _ := server.Respond(reply)
	if _, _, err := client.Finish(response); err != nil {
		t.Fatal(err)
	}
	metrics := NewMetrics()
	owner, err := NewServer(Options{Keys: []ControlKey{{Private: control, NotAfter: time.Now().Add(time.Hour)}},
		Handler: &recordingHandler{}, Logger: slog.New(slog.DiscardHandler), Metrics: metrics, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	return newSession(owner, transport, coreNoise, control, server.Machine(), server.Hello(), reply), metrics
}

// A message gets 30 s plus its size at 64 KiB/s, at most 10 minutes; no
// record deadline goes past it.
func TestSendDeadlineBoundsTheWholeMessage(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_800_000_000, 0)
	if got := sendDeadline(start, 0); !got.Equal(start.Add(30 * time.Second)) {
		t.Fatalf("empty message deadline = %v", got.Sub(start))
	}
	if got := sendDeadline(start, 64*1024*60); !got.Equal(start.Add(90 * time.Second)) {
		t.Fatalf("3.75 MiB deadline = %v, want 90s", got.Sub(start))
	}
	if got := sendDeadline(start, 1<<30); !got.Equal(start.Add(10 * time.Minute)) {
		t.Fatalf("1 GiB deadline = %v, want the 10 minute cap", got.Sub(start))
	}

	// Now() moves 25 s per call: the record's own 10 s deadline would end
	// after the message deadline, so the message deadline wins.
	var mu sync.Mutex
	clock := start
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(25 * time.Second)
		return clock
	}
	transport := &deadlineTransport{failAfter: -1}
	session, _ := deadlineSession(t, now, transport)
	if err := session.Send(sharedmtcp.MessageError, &mtcpv1.Error{Message: "small"}); err != nil {
		t.Fatalf("a message sent in time failed: %v", err)
	}
	// The message deadline is 25 s (first Now) + 30 s + a few microseconds for
	// its bytes; the record's own would have been 50 s + 10 s.
	messageDeadline := start.Add(25*time.Second + sendDeadlineBase)
	if len(transport.deadlines) != 1 || transport.deadlines[0].Before(messageDeadline) ||
		!transport.deadlines[0].Before(messageDeadline.Add(time.Second)) {
		t.Fatalf("record deadlines = %v, want the message deadline", transport.deadlines)
	}
}

// The original fault: a node that takes each 64 KiB record just inside its
// own 10 s deadline. The message deadline now ends it, and no record of the
// message is ever given a deadline past the message's.
func TestSendDeadlineEndsADrippingReader(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_800_000_000, 0)
	var mu sync.Mutex
	clock := start
	peek := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return clock
	}
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		clock = clock.Add(9 * time.Second) // one record every 9 s
		return clock
	}
	transport := &deadlineTransport{failAfter: -1, now: peek}
	session, metrics := deadlineSession(t, now, transport)
	// 1 MiB of relay map: 16 records, a deadline of 30 s + 16 s.
	snapshot := &mtcpv1.MapSnapshot{RelayMap: bytes.Repeat([]byte{0x5a}, 1<<20)}
	err := session.Send(sharedmtcp.MessageMapSnapshot, snapshot)
	if !errors.Is(err, errSendDeadline) || !transport.closed {
		t.Fatalf("dripping reader = %v, transport closed %t", err, transport.closed)
	}
	overall := start.Add(9*time.Second + sendDeadlineBase + 16*time.Second)
	for index, deadline := range transport.deadlines {
		if deadline.After(overall.Add(time.Second)) {
			t.Fatalf("record %d deadline %v past the message deadline %v", index, deadline.Sub(start), overall.Sub(start))
		}
	}
	if len(transport.deadlines) >= 16 {
		t.Fatalf("all %d records went out to a dripping reader", len(transport.deadlines))
	}
	if got := sessionLimitCount(t, metrics, limitSendDeadline); got != 1 {
		t.Fatalf("send_deadline counted %v times, want 1", got)
	}
}

// A reader that stalls past the message deadline ends the session, counted.
func TestSendDeadlineEndsAStalledSession(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_800_000_000, 0)
	calls := 0
	var mu sync.Mutex
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls > 2 {
			return start.Add(11 * time.Minute)
		}
		return start
	}
	transport := &deadlineTransport{failAfter: 0}
	session, metrics := deadlineSession(t, now, transport)
	err := session.Send(sharedmtcp.MessageError, &mtcpv1.Error{Message: "slow"})
	if !errors.Is(err, errSendDeadline) || !transport.closed {
		t.Fatalf("stalled send = %v, transport closed %t", err, transport.closed)
	}
	if got := sessionLimitCount(t, metrics, limitSendDeadline); got != 1 {
		t.Fatalf("send_deadline limit counted %v times, want 1", got)
	}
	// A failure before the deadline is an ordinary write error.
	early := &deadlineTransport{failAfter: 0}
	quiet, _ := deadlineSession(t, func() time.Time { return start }, early)
	if err := quiet.Send(sharedmtcp.MessageError, &mtcpv1.Error{Message: "x"}); err == nil ||
		errors.Is(err, errSendDeadline) {
		t.Fatalf("early write failure = %v", err)
	}
}

func sessionLimitCount(t *testing.T, metrics *Metrics, limit string) float64 {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.Collectors()...)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "meshtransit_mtcp_session_limits_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metric.GetLabel()[0].GetValue() == limit {
				return metric.GetCounter().GetValue()
			}
		}
	}
	return 0
}

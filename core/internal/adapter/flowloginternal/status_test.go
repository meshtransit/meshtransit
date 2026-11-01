package flowloginternal

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/network"
)

func post(t *testing.T, client *http.Client, target string, body []byte, header http.Header) (answer, error) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		request.Header[name] = values
	}
	response, err := client.Do(request)
	if err != nil {
		return answer{}, err
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, response.Body)
	return answer{status: response.StatusCode, header: response.Header}, nil
}

// testReportedAt is a report's time: the fixtures' clocks start at the
// wall clock and move by seconds.
var testReportedAt = time.Now().UnixMilli()

func testReport(networks ...int) *flowlogv1.FlowStatus {
	report := &flowlogv1.FlowStatus{
		InstanceId: bytes.Repeat([]byte{7}, 16), AcceptedVersions: []uint32{1},
		NoiseFingerprints: [][]byte{bytes.Repeat([]byte{9}, 32)}, SealingKeyIds: []string{"meshflow-1"},
		ReportedAtMs: testReportedAt,
	}
	for _, index := range networks {
		workspaceID, networkID := testID(1).Bytes(), testID(index).Bytes()
		report.Networks = append(report.Networks, &flowlogv1.FlowStatus_Network{
			WorkspaceId: workspaceID[:], NetworkId: networkID[:], TestedEtag: bytes.Repeat([]byte{3}, 16),
			TestResult: flowlogv1.FlowStatus_TEST_OK, TestedAtMs: testReportedAt - 10_000,
			DeliveryError: flowlogv1.FlowStatus_DELIVERY_NONE, Lost_24H: 2,
		})
	}
	return report
}

func encode(t *testing.T, message proto.Message) []byte {
	t.Helper()
	body, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// A report is written with its Networks sorted; a newer receiver's fields
// and enum values never fail it (review s4c3 H1).
func TestStatusReport(t *testing.T) {
	reader := &fakeReader{}
	f := startServerWith(t, reader)
	client := f.receiver(t)
	report := testReport(30, 20)
	report.Networks[0].TestResult = flowlogv1.FlowStatus_TestResult(99)
	report.Networks[1].LastDeliveredAtMs = testReportedAt + 60_000 // after the report: not believed
	body := encode(t, report)
	body = protowire.AppendTag(body, 99, protowire.BytesType) // a field of a newer receiver
	body = protowire.AppendBytes(body, []byte("future"))
	if response, err := post(t, client, f.base+statusPath, body, nil); err != nil ||
		response.status != http.StatusNoContent {
		t.Fatalf("POST status = %v, %v", response, err)
	}
	if len(reader.reports) != 1 {
		t.Fatalf("%d reports written", len(reader.reports))
	}
	written := reader.reports[0]
	if written.Instance[0] != 7 || written.AcceptedVersions[0] != 1 || written.NoiseFingerprints[0][0] != 9 ||
		!written.ReportedAt.Equal(time.UnixMilli(testReportedAt)) || len(written.Networks) != 2 ||
		!written.Networks[0].LastDeliveredAt.IsZero() || written.Networks[0].TestedAt.IsZero() ||
		written.Networks[0].Network != network.ID(testID(20)) ||
		written.Networks[1].TestResult != connectionlog.ReceiverUnspecified ||
		written.Networks[0].TestResult != connectionlog.TestOK || written.Networks[0].Lost != 2 ||
		written.Networks[0].DeliveryError != connectionlog.DeliveryNone || len(written.Networks[0].TestedETag) != 16 {
		t.Fatalf("report = %+v", written)
	}
	// A heartbeat without Networks is a report too.
	if response, _ := post(t, client, f.base+statusPath, encode(t, testReport()), nil); response.status !=
		http.StatusNoContent {
		t.Fatalf("a heartbeat: %v", response)
	}
	if response, _, _ := get(t, client, f.base+statusPath, nil); response.status != http.StatusMethodNotAllowed ||
		response.header.Get("Allow") != http.MethodPost {
		t.Fatalf("GET status: %v", response)
	}
}

// What a report may not be: everything is refused, nothing written.
func TestStatusRefusals(t *testing.T) {
	reader := &fakeReader{}
	f := startServerWith(t, reader)
	client := f.receiver(t)
	change := func(edit func(*flowlogv1.FlowStatus)) []byte {
		report := testReport(20)
		edit(report)
		return encode(t, report)
	}
	for name, body := range map[string][]byte{
		"garbage":          {0xff, 0xff, 0xff},
		"short instance":   change(func(r *flowlogv1.FlowStatus) { r.InstanceId = []byte{1} }),
		"zero instance":    change(func(r *flowlogv1.FlowStatus) { r.InstanceId = make([]byte, 16) }),
		"no time":          change(func(r *flowlogv1.FlowStatus) { r.ReportedAtMs = 0 }),
		"from the future":  change(func(r *flowlogv1.FlowStatus) { r.ReportedAtMs = testReportedAt + 3_600_000 }),
		"a day old":        change(func(r *flowlogv1.FlowStatus) { r.ReportedAtMs = testReportedAt - 25*3_600_000 }),
		"far future":       change(func(r *flowlogv1.FlowStatus) { r.ReportedAtMs = 1 << 62 }),
		"no version":       change(func(r *flowlogv1.FlowStatus) { r.AcceptedVersions = nil }),
		"version zero":     change(func(r *flowlogv1.FlowStatus) { r.AcceptedVersions = []uint32{0} }),
		"no fingerprint":   change(func(r *flowlogv1.FlowStatus) { r.NoiseFingerprints = nil }),
		"short print":      change(func(r *flowlogv1.FlowStatus) { r.NoiseFingerprints = [][]byte{{1}} }),
		"bad sealing key":  change(func(r *flowlogv1.FlowStatus) { r.SealingKeyIds = []string{"a b"} }),
		"twice":            encode(t, testReport(20, 20)),
		"bad network":      change(func(r *flowlogv1.FlowStatus) { r.Networks[0].NetworkId = []byte{1, 2} }),
		"not a v7 network": change(func(r *flowlogv1.FlowStatus) { r.Networks[0].NetworkId = make([]byte, 16) }),
		"short tag":        change(func(r *flowlogv1.FlowStatus) { r.Networks[0].TestedEtag = []byte{1} }),
		"negative time":    change(func(r *flowlogv1.FlowStatus) { r.Networks[0].TestedAtMs = -1 }),
	} {
		f.clock.advance(time.Second)
		if response, err := post(t, client, f.base+statusPath, body, nil); err != nil ||
			response.status != http.StatusBadRequest {
			t.Errorf("%s: %v, %v", name, response, err)
		}
	}
	many := testReport()
	for index := range connectionlog.MaxReceiverReportNetworks + 1 {
		many.Networks = append(many.Networks, testReport(100 + index).Networks[0])
	}
	f.clock.advance(time.Second)
	if response, _ := post(t, client, f.base+statusPath, encode(t, many), nil); response.status !=
		http.StatusBadRequest && response.status != http.StatusRequestEntityTooLarge {
		t.Errorf("too many Networks: %v", response)
	}
	f.clock.advance(time.Second)
	if response, _ := post(t, client, f.base+statusPath, bytes.Repeat([]byte{0}, maxStatusBody+1), nil); response.status !=
		http.StatusRequestEntityTooLarge {
		t.Errorf("a large body: %v", response)
	}
	f.clock.advance(time.Second)
	if response, _ := post(t, client, f.base+statusPath, encode(t, testReport(20)),
		http.Header{"Content-Encoding": {"gzip"}}); response.status != http.StatusUnsupportedMediaType {
		t.Errorf("a compressed body: %v", response)
	}
	if len(reader.reports) != 0 {
		t.Fatalf("refused reports were written: %d", len(reader.reports))
	}
	// Past the burst, reports wait for the rate.
	throttled := false
	for range statusBurst + 1 {
		if response, _ := post(t, client, f.base+statusPath, []byte{0xff}, nil); response.status ==
			http.StatusTooManyRequests {
			throttled = true
		}
	}
	if !throttled {
		t.Error("no report was throttled past the burst")
	}
	f.clock.advance(10 * time.Second)
	for err, status := range map[error]int{
		errors.Join(ErrReportStaleClock, errors.New("store")): http.StatusBadRequest,
		ErrTooManyReceivers:         http.StatusTooManyRequests,
		errors.New("database down"): http.StatusServiceUnavailable,
	} {
		reader.set(func(r *fakeReader) { r.reportErr = err })
		f.clock.advance(time.Second)
		if response, _ := post(t, client, f.base+statusPath, encode(t, testReport(20)), nil); response.status != status {
			t.Errorf("%v: %v, want %d", err, response, status)
		}
	}
}

// One report is written at a time per replica; others are told to come
// back, and the reads are never held up by it (review s4c3 H2).
func TestStatusOneWriteAtATime(t *testing.T) {
	reader := &fakeReader{reportBlock: make(chan struct{})}
	f := startServerWith(t, reader)
	client := f.receiver(t)
	var wait sync.WaitGroup
	first := make(chan int, 1)
	wait.Go(func() {
		response, err := post(t, client, f.base+statusPath, encode(t, testReport(20)), nil)
		if err != nil {
			first <- 0
			return
		}
		first <- response.status
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		reader.mu.Lock()
		entered := reader.reportsEntered
		reader.mu.Unlock()
		if entered == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if response, _ := post(t, client, f.base+statusPath, encode(t, testReport(21)), nil); response.status !=
		http.StatusServiceUnavailable {
		t.Errorf("a second report while one is written: %v", response)
	}
	if response, _, _ := get(t, client, f.base+keysPath, nil); response.status != http.StatusOK {
		t.Errorf("a read while a report is written: %v", response)
	}
	close(reader.reportBlock)
	wait.Wait()
	if status := <-first; status != http.StatusNoContent {
		t.Fatalf("the first report: %d", status)
	}
}

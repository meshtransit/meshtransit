package flowreport

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/client/internal/flowcount"
)

var spoolNow = time.UnixMilli(1_800_000_000_000)

func testWindow(records int, end time.Time) flowcount.Window {
	window := flowcount.Window{StartMS: end.Add(-time.Minute).UnixMilli(), EndMS: end.UnixMilli()}
	for index := range records {
		window.Records = append(window.Records, &flowlogv1.FlowRecord{
			Kind: flowlogv1.FlowRecord_FLOW, Class: flowlogv1.FlowRecord_MESH, Protocol: 6,
			Direction: flowlogv1.FlowRecord_OUTBOUND, DestinationPort: uint32(index),
			FirstSeenMs: window.StartMS, LastSeenMs: window.EndMS,
		})
	}
	return window
}

func openTestSpool(t *testing.T, dir string, limits Limits) *Spool {
	t.Helper()
	spool, err := OpenSpool(dir, limits, spoolNow)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = spool.Close() })
	return spool
}

func decode(t *testing.T, compressed []byte) *flowlogv1.FlowBatch {
	t.Helper()
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	batch := &flowlogv1.FlowBatch{}
	if err := proto.Unmarshal(plain, batch); err != nil {
		t.Fatal(err)
	}
	return batch
}

var testPolicy = Policy{MapRevision: 7, Digest: bytes.Repeat([]byte{1}, 32)}

// Batches go out oldest first, carry their sequence and held_from, and
// leave once committed.
func TestSpoolOrderAndCommit(t *testing.T) {
	t.Parallel()
	spool := openTestSpool(t, filepath.Join(t.TempDir(), "spool"), DiskLimits())
	for index := range 3 {
		if err := spool.Add(testWindow(index+1, spoolNow), testPolicy, 60, spoolNow); err != nil {
			t.Fatal(err)
		}
	}
	pending, ok, err := spool.Oldest()
	if err != nil || !ok || pending.Request.GetSequence() != 1 || pending.Request.GetHeldFrom() != 1 {
		t.Fatalf("oldest %v %v %v", pending.Request, ok, err)
	}
	batch := decode(t, pending.Compressed)
	if batch.GetReporterSequence() != 1 || !bytes.Equal(batch.GetBootId(), pending.Request.GetBootId()) ||
		len(batch.GetRecords()) != 1 || batch.GetMapRevision() != 7 || len(batch.GetPolicyDigest()) != 32 {
		t.Fatalf("batch %v", batch)
	}
	if err := spool.Commit(pending.Request.GetBootId(), 2); err != nil {
		t.Fatal(err)
	}
	if pending, ok, _ = spool.Oldest(); !ok || pending.Request.GetSequence() != 3 || pending.Request.GetHeldFrom() != 3 {
		t.Fatalf("after commit %v", pending.Request)
	}
	if _, ok, _ := spool.Get(2); ok {
		t.Fatal("a committed batch is still held")
	}
	if err := spool.Commit(pending.Request.GetBootId(), 4); err == nil {
		t.Fatal("a commit past the last batch was taken")
	}
	if spool.Highest() != 3 {
		t.Fatalf("highest %d", spool.Highest())
	}
}

// A spool goes on after a restart with the same boot and batches.
func TestSpoolSurvivesRestart(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "spool")
	spool, err := OpenSpool(dir, DiskLimits(), spoolNow)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := spool.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow); err != nil {
			t.Fatal(err)
		}
	}
	first, _, _ := spool.Oldest()
	_ = spool.Close()
	// A stray temporary file and a foreign file are left alone or cleared.
	if err := os.WriteFile(filepath.Join(dir, "00000000000000000002.batch.tmp-aa"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened := openTestSpool(t, dir, DiskLimits())
	again, ok, err := reopened.Oldest()
	if err != nil || !ok || !proto.Equal(again.Request, first.Request) || !bytes.Equal(again.Compressed, first.Compressed) {
		t.Fatalf("after restart %v %v", again.Request, err)
	}
	if err := reopened.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow); err != nil || reopened.Highest() != 3 {
		t.Fatalf("next after restart %d %v", reopened.Highest(), err)
	}
	if _, err := os.Stat(filepath.Join(dir, "00000000000000000002.batch.tmp-aa")); !os.IsNotExist(err) {
		t.Fatal("a temporary file was kept")
	}
}

// Past its limits the spool drops the oldest batches into one lost range,
// which leaves once committed past.
func TestSpoolDropsIntoLost(t *testing.T) {
	t.Parallel()
	spool := openTestSpool(t, filepath.Join(t.TempDir(), "spool"), Limits{MaxBytes: 1, MaxAge: time.Hour})
	for index := range 3 {
		if err := spool.Add(testWindow(2, spoolNow.Add(time.Duration(index)*time.Minute)), testPolicy, 60, spoolNow); err != nil {
			t.Fatal(err)
		}
	}
	pending, ok, _ := spool.Oldest()
	lost := pending.Request.GetLost()
	if !ok || pending.Request.GetSequence() != 3 || pending.Request.GetHeldFrom() != 3 || lost.GetFirstSequence() != 1 ||
		lost.GetLastSequence() != 2 || lost.GetRecords() != 4 || lost.GetFromMs() >= lost.GetToMs() {
		t.Fatalf("pending %v", pending.Request)
	}
	if err := spool.Commit(pending.Request.GetBootId(), 2); err != nil {
		t.Fatal(err)
	}
	if pending, _, _ = spool.Oldest(); pending.Request.GetLost() != nil {
		t.Fatal("a committed lost range was kept")
	}
	// A window older than MaxAge leaves too.
	aged := openTestSpool(t, filepath.Join(t.TempDir(), "spool"), Limits{MaxBytes: 1 << 20, MaxAge: time.Hour})
	_ = aged.Add(testWindow(1, spoolNow.Add(-2*time.Hour)), testPolicy, 60, spoolNow)
	_ = aged.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow)
	if pending, _, _ := aged.Oldest(); pending.Request.GetSequence() != 2 || pending.Request.GetLost().GetLastSequence() != 1 {
		t.Fatalf("aged %v", pending.Request)
	}
}

// A damaged state starts a new boot; a damaged batch is left out.
func TestSpoolDamage(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "spool")
	spool, err := OpenSpool(dir, DiskLimits(), spoolNow)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		_ = spool.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow)
	}
	before, _, _ := spool.Oldest()
	_ = spool.Close()
	if err := os.WriteFile(filepath.Join(dir, batchName(1)), []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenSpool(dir, DiskLimits(), spoolNow)
	if err != nil {
		t.Fatal(err)
	}
	pending, _, _ := reopened.Oldest()
	if pending.Request.GetSequence() != 2 || !bytes.Equal(pending.Request.GetBootId(), before.Request.GetBootId()) {
		t.Fatalf("after a damaged batch %v", pending.Request)
	}
	_ = reopened.Close()
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	fresh := openTestSpool(t, dir, DiskLimits())
	if _, ok, _ := fresh.Oldest(); ok || fresh.Highest() != 0 {
		t.Fatal("a damaged state kept its batches")
	}
	if err := fresh.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow); err != nil {
		t.Fatal(err)
	}
	if pending, _, _ := fresh.Oldest(); bytes.Equal(pending.Request.GetBootId(), before.Request.GetBootId()) {
		t.Fatal("a new boot kept the old boot id")
	}
}

func TestSpoolReset(t *testing.T) {
	t.Parallel()
	spool := openTestSpool(t, filepath.Join(t.TempDir(), "spool"), DiskLimits())
	_ = spool.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow)
	before, _, _ := spool.Oldest()
	if err := spool.Reset(); err != nil {
		t.Fatal(err)
	}
	_ = spool.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow)
	after, _, _ := spool.Oldest()
	if after.Request.GetSequence() != 1 || bytes.Equal(after.Request.GetBootId(), before.Request.GetBootId()) {
		t.Fatalf("after reset %v", after.Request)
	}
}

// A window longer than twice window_s keeps its last part, and its records
// are clamped into it.
func TestBuildBatchClampsLongWindows(t *testing.T) {
	t.Parallel()
	window := testWindow(1, spoolNow)
	window.StartMS = spoolNow.Add(-10 * time.Hour).UnixMilli()
	window.Records[0].FirstSeenMs = window.StartMS
	window.Overflow = flowcount.Overflow{Keys: 1, Packets: 2, Bytes: 3}
	built, err := buildBatch(window, [16]byte{1}, 9, Policy{}, 60)
	if err != nil {
		t.Fatal(err)
	}
	batch := decode(t, built.compressed)
	if batch.GetWindowEndMs()-batch.GetWindowStartMs() != 120_000 ||
		batch.GetRecords()[0].GetFirstSeenMs() != batch.GetWindowStartMs() || batch.GetOverflow().GetPackets() != 2 ||
		len(batch.GetPolicyDigest()) != 0 || batch.GetReporterSequence() != 9 {
		t.Fatalf("batch %v", batch)
	}
}

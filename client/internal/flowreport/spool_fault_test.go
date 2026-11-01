package flowreport

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/client/internal/flowcount"
)

var errDiskFull = errors.New("disk full")

// faultyWrites fails writes of name while failing is set.
type faultyWrites struct {
	mu      sync.Mutex
	name    string
	failing bool
}

func (f *faultyWrites) write(root *os.Root, name string, content []byte) error {
	f.mu.Lock()
	fail := f.failing && name == f.name
	f.mu.Unlock()
	if fail {
		return errDiskFull
	}
	return writeAtomic(root, name, content)
}

func (f *faultyWrites) set(name string, failing bool) {
	f.mu.Lock()
	f.name, f.failing = name, failing
	f.mu.Unlock()
}

// checkPending holds a request to flowlog-v1 §6 and the spool's invariants.
func checkPending(t *testing.T, pending Pending) {
	t.Helper()
	request := pending.Request
	if len(request.GetBootId()) != 16 || request.GetSequence() == 0 || request.GetHeldFrom() == 0 ||
		request.GetHeldFrom() > request.GetSequence() || len(pending.Compressed) == 0 {
		t.Fatalf("request %v", request)
	}
	if lost := request.GetLost(); lost != nil && (lost.GetFirstSequence() == 0 ||
		lost.GetFirstSequence() > lost.GetLastSequence() || lost.GetLastSequence() >= request.GetHeldFrom()) {
		t.Fatalf("lost %v for held_from %d", lost, request.GetHeldFrom())
	}
}

// A state that cannot be saved never lets a sequence carry two contents:
// the sequence is reused only for a batch that was never offered.
func TestSpoolFailedStateSave(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "spool")
	faults := &faultyWrites{}
	spool, err := openSpool(dir, DiskLimits(), spoolNow, faults.write)
	if err != nil {
		t.Fatal(err)
	}
	if err := spool.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow); err != nil {
		t.Fatal(err)
	}
	faults.set(stateFile, true)
	if err := spool.Add(testWindow(2, spoolNow), testPolicy, 60, spoolNow); !errors.Is(err, errDiskFull) {
		t.Fatalf("add with a full disk: %v", err)
	}
	if spool.Highest() != 1 {
		t.Fatalf("a failed add used sequence %d", spool.Highest())
	}
	if _, err := os.Stat(filepath.Join(dir, batchName(2))); !os.IsNotExist(err) {
		t.Fatal("the failed batch's file was left")
	}
	if _, ok, _ := spool.Get(2); ok {
		t.Fatal("a failed batch is offered")
	}
	// A failed reset leaves the old boot in use.
	before, _, _ := spool.Oldest()
	if err := spool.Reset(); !errors.Is(err, errDiskFull) {
		t.Fatalf("reset with a full disk: %v", err)
	}
	after, _, _ := spool.Oldest()
	if string(after.Request.GetBootId()) != string(before.Request.GetBootId()) {
		t.Fatal("a failed reset changed the boot")
	}
	faults.set("", false)
	if err := spool.Add(testWindow(3, spoolNow), testPolicy, 60, spoolNow); err != nil || spool.Highest() != 2 {
		t.Fatalf("after the disk recovered: %d %v", spool.Highest(), err)
	}
	_ = spool.Close()
}

// Files the state does not hold (at or below the lost range, at or past
// next) are removed on open, and a hole makes what is older lost.
func TestSpoolLoadRepairs(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "spool")
	spool, err := OpenSpool(dir, Limits{MaxBytes: 1, MaxAge: time.Hour}, spoolNow)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		_ = spool.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow)
	}
	boot := spool.boot
	_ = spool.Close()
	// File 1 comes back (a removal that failed); a stray file past next.
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	raw, err := root.ReadFile(batchName(3))
	if err != nil {
		t.Fatal(err)
	}
	for _, sequence := range []uint64{1, 9} {
		if err := root.WriteFile(batchName(sequence), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reopened := openTestSpool(t, dir, DiskLimits())
	pending, ok, err := reopened.Oldest()
	if err != nil || !ok || pending.Request.GetSequence() != 3 || pending.Request.GetLost().GetLastSequence() != 2 {
		t.Fatalf("after repairs %v %v", pending.Request, err)
	}
	checkPending(t, pending)
	for _, sequence := range []uint64{1, 9} {
		if _, err := os.Stat(filepath.Join(dir, batchName(sequence))); !os.IsNotExist(err) {
			t.Errorf("file %d kept", sequence)
		}
	}
	// A hole: 4 and 5 made, 4 removed behind the spool's back.
	_ = reopened.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow)
	_ = reopened.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow)
	_ = reopened.Close()
	if err := os.Remove(filepath.Join(dir, batchName(4))); err != nil {
		t.Fatal(err)
	}
	holed := openTestSpool(t, dir, DiskLimits())
	pending, _, _ = holed.Oldest()
	if pending.Request.GetSequence() != 5 || pending.Request.GetLost().GetLastSequence() != 4 ||
		pending.Request.GetLost().GetFirstSequence() != 1 || holed.boot != boot {
		t.Fatalf("after a hole %v", pending.Request)
	}
	checkPending(t, pending)
}

// A batch whose bytes changed on disk is lost, not resent forever.
func TestSpoolCorruptBatch(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "spool")
	spool := openTestSpool(t, dir, DiskLimits())
	for range 3 {
		_ = spool.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	raw, _ := root.ReadFile(batchName(2))
	raw[len(raw)-1] ^= 1
	if err := root.WriteFile(batchName(2), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	pending, ok, err := spool.Get(2)
	if err != nil || !ok || pending.Request.GetSequence() != 3 || pending.Request.GetLost().GetLastSequence() != 2 {
		t.Fatalf("after a corrupt batch %v %v", pending.Request, err)
	}
	checkPending(t, pending)
	if _, ok, _ := spool.Get(1); ok {
		t.Fatal("a batch older than a corrupt one is still offered")
	}
}

// An answer for another boot commits nothing.
func TestSpoolCommitChecksBoot(t *testing.T) {
	t.Parallel()
	spool := openTestSpool(t, filepath.Join(t.TempDir(), "spool"), DiskLimits())
	_ = spool.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow)
	if err := spool.Commit(make([]byte, 16), 1); err == nil {
		t.Fatal("a commit for another boot was taken")
	}
	if _, ok, _ := spool.Oldest(); !ok {
		t.Fatal("another boot's commit dropped a batch")
	}
}

// Every request the spool offers holds to flowlog-v1 §6, through adds,
// drops into lost, commits and gets, also concurrently.
func TestSpoolRequestsAlwaysValid(t *testing.T) {
	t.Parallel()
	spool := openTestSpool(t, filepath.Join(t.TempDir(), "spool"), Limits{MaxBytes: 2000, MaxAge: time.Hour})
	var group sync.WaitGroup
	group.Go(func() {
		for index := range 200 {
			if err := spool.Add(testWindow(index%7+1, spoolNow), testPolicy, 60, spoolNow); err != nil {
				t.Error(err)
				return
			}
		}
	})
	for range 400 {
		pending, ok, err := spool.Oldest()
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			continue
		}
		checkPending(t, pending)
		if again, ok, _ := spool.Get(pending.Request.GetSequence() + 1); ok {
			checkPending(t, again)
		}
		if pending.Request.GetSequence()%3 == 0 {
			_ = spool.Commit(pending.Request.GetBootId(), pending.Request.GetSequence())
		}
	}
	group.Wait()
}

// Limits apply on open too.
func TestSpoolLimitsOnOpen(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "spool")
	spool, err := OpenSpool(dir, DiskLimits(), spoolNow)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		_ = spool.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow)
	}
	_ = spool.Close()
	small := openTestSpool(t, dir, Limits{MaxBytes: 1, MaxAge: time.Hour})
	if pending, _, _ := small.Oldest(); pending.Request.GetSequence() != 3 || pending.Request.GetLost() == nil {
		t.Fatalf("after a smaller limit %v", pending.Request)
	}
}

func TestSpoolPermissions(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("ACLs, not mode bits")
	}
	dir := filepath.Join(t.TempDir(), "spool")
	spool := openTestSpool(t, dir, DiskLimits())
	_ = spool.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow)
	for name, want := range map[string]os.FileMode{
		dir: 0o700, filepath.Join(dir, batchName(1)): 0o600,
		filepath.Join(dir, stateFile): 0o600,
	} {
		info, err := os.Stat(name)
		if err != nil || info.Mode().Perm() != want {
			t.Errorf("%s: %v %v", name, info.Mode().Perm(), err)
		}
	}
}

func TestBuildBatchEdges(t *testing.T) {
	t.Parallel()
	window := testWindow(1, spoolNow)
	window.StartMS = window.EndMS
	window.Records[0].LastSeenMs = window.StartMS - 1000
	built, err := buildBatch(window, [16]byte{1}, 1, Policy{}, 60)
	if err != nil || built.toMS <= built.fromMS {
		t.Fatalf("an empty window %v %v", built, err)
	}
	record := decode(t, built.compressed).GetRecords()[0]
	if record.GetLastSeenMs() < record.GetFirstSeenMs() {
		t.Fatalf("record %v", record)
	}
	window.Records = make([]*flowlogv1.FlowRecord, flowcount.MaxWindowRecords+1)
	if _, err := buildBatch(window, [16]byte{1}, 1, Policy{}, 60); !errors.Is(err, ErrBatchTooLarge) {
		t.Fatalf("too many records: %v", err)
	}
}

// A counted batch whose file is missing at the end makes the older ones
// lost, so the next batch follows held_from in order.
func TestSpoolTailGap(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "spool")
	spool, err := OpenSpool(dir, DiskLimits(), spoolNow)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		_ = spool.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow)
	}
	_ = spool.Close()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Remove(batchName(3)); err != nil {
		t.Fatal(err)
	}
	_ = root.Close()
	reopened := openTestSpool(t, dir, DiskLimits())
	if _, ok, _ := reopened.Oldest(); ok {
		t.Fatal("batches before a missing last one are still offered")
	}
	if err := reopened.Add(testWindow(1, spoolNow), testPolicy, 60, spoolNow); err != nil {
		t.Fatal(err)
	}
	pending, _, _ := reopened.Oldest()
	lost := pending.Request.GetLost()
	if pending.Request.GetSequence() != 4 || lost.GetFirstSequence() != 1 || lost.GetLastSequence() != 3 ||
		lost.GetFromMs() == 0 {
		t.Fatalf("after a tail gap %v", pending.Request)
	}
	checkPending(t, pending)
}

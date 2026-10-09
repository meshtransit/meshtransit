package mapsession

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/policydigest"
)

type recordingEnforcementRecorder struct {
	mu      sync.Mutex
	reports []Enforcement
	stale   bool
	fail    bool
}

func (recorder *recordingEnforcementRecorder) RecordEnforcement(ctx context.Context,
	enforcement Enforcement) (bool, error) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if _, bounded := ctx.Deadline(); !bounded {
		return false, errors.New("unbounded enforcement record")
	}
	if recorder.fail {
		return false, errors.New("synthetic enforcement store failure")
	}
	recorder.reports = append(recorder.reports, enforcement)
	return !recorder.stale, nil
}

func (recorder *recordingEnforcementRecorder) state() []Enforcement {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	return append([]Enforcement(nil), recorder.reports...)
}

// revisionDigest is a FilterDigester whose digest follows the Network revision,
// so a test can tell which snapshot a delivery recorded.
func revisionDigest(snapshot Snapshot) (FilterDigest, error) {
	var digest policydigest.Digest
	digest[0] = byte(snapshot.NetworkRevision())
	digest[1] = 0xa5
	return NewFilterDigest(digest, int(snapshot.NetworkRevision()))
}

func TestStreamServiceRecordsDeliveredFilterAndAcceptsEnforcementReports(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		initial, advanced, _ := authorityDeltaSnapshotsFixture(t)
		opener := &streamSnapshotOpener{snapshots: []Snapshot{initial, advanced}}
		revisions := newStreamRevisionWatcher()
		options := streamOptionsFixture(t)
		options.FilterDigest = revisionDigest
		base, err := NewStreamService(opener, &streamPresenceStore{}, revisions, newStreamConnectivityWatcher(),
			options)
		if err != nil {
			t.Fatal(err)
		}
		deliveries := &recordingDeliveryRecorder{}
		reports := &recordingEnforcementRecorder{}
		service, err := base.WithDeliveryRecorder(deliveries)
		if err != nil {
			t.Fatal(err)
		}
		if service, err = service.WithEnforcementRecorder(reports); err != nil {
			t.Fatal(err)
		}
		machine, request := authenticatedRequestFixture(t, initial)
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- service.Serve(ctx, machine, request, &recordingStreamSink{}) }()
		synctest.Wait()
		recorded, _ := deliveries.state()
		if want, _ := revisionDigest(initial); len(recorded) != 1 || recorded[0].Filter != want ||
			recorded[0].NodeKey != initial.NodeKey() ||
			recorded[0].MachineFingerprint != initial.MachineKey().Fingerprint() || !recorded[0].IsValid() {
			t.Fatalf("initial deliveries = %+v", recorded)
		}
		advanceRevision(t, revisions, initial, advanced)
		synctest.Wait()
		recorded, _ = deliveries.state()
		if want, _ := revisionDigest(advanced); len(recorded) != 2 || recorded[1].Filter != want {
			t.Fatalf("deliveries after advance = %+v", recorded)
		}
		cancel()
		synctest.Wait()
		if err := <-result; !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve() error = %v", err)
		}

		// Reports need no stream on this replica: the recorder finds the session.
		report := ClientEnforcement{NodeKey: initial.NodeKey(), AppliedAt: time.Now()}
		report.Filter, _ = revisionDigest(advanced)
		if err := service.ReportEnforcement(t.Context(), machine, report); err != nil {
			t.Fatalf("ReportEnforcement() error = %v", err)
		}
		stored := reports.state()
		if len(stored) != 1 || stored[0].NodeKey != initial.NodeKey() ||
			stored[0].MachineFingerprint != initial.MachineKey().Fingerprint() ||
			stored[0].Filter != report.Filter || !stored[0].IsValid() {
			t.Fatalf("stored reports = %+v", stored)
		}
		other, err := control.NewAuthenticatedMachine(node.MachineKey{0x77})
		if err != nil {
			t.Fatal(err)
		}
		if err := service.ReportEnforcement(t.Context(), other, report); err != nil {
			t.Fatal(err)
		}
		if stored = reports.state(); stored[1].MachineFingerprint == initial.MachineKey().Fingerprint() {
			t.Fatal("a report was bound to a machine other than the one that sent it")
		}
		future := report
		future.AppliedAt = time.Now().Add(2 * maximumAppliedSkew)
		if err := service.ReportEnforcement(t.Context(), machine, future); !errors.Is(err, ErrInvalidEnforcementReport) {
			t.Fatalf("report from the future = %v, want ErrInvalidEnforcementReport", err)
		}
		slightlyAhead := report
		slightlyAhead.AppliedAt = time.Now().Add(time.Second)
		if err := service.ReportEnforcement(t.Context(), machine, slightlyAhead); err != nil {
			t.Fatalf("report with small skew = %v", err)
		}
		if stored = reports.state(); len(stored) != 3 || !stored[2].AppliedAt.Equal(stored[2].ReportedAt) {
			t.Fatalf("skewed report was not clamped: %+v", stored)
		}
		reports.stale = true
		if err := service.ReportEnforcement(t.Context(), machine, report); !errors.Is(err, ErrNoEnforcementStream) {
			t.Fatalf("report without a current session = %v, want ErrNoEnforcementStream", err)
		}
		reports.stale, reports.fail = false, true
		if err := service.ReportEnforcement(t.Context(), machine, report); !errors.Is(err, ErrEnforcementUnavailable) {
			t.Fatalf("report with a failed store = %v, want ErrEnforcementUnavailable", err)
		}
	})
}

func TestReportEnforcementRequiresRecorderAndValidReport(t *testing.T) {
	initial, _, _ := authorityDeltaSnapshotsFixture(t)
	service := newStreamServiceFixture(t, &streamSnapshotOpener{snapshots: []Snapshot{initial}}, &streamPresenceStore{})
	machine, _ := authenticatedRequestFixture(t, initial)
	filter, _ := revisionDigest(initial)
	report := ClientEnforcement{NodeKey: initial.NodeKey(), Filter: filter, AppliedAt: time.Now()}
	if err := service.ReportEnforcement(t.Context(), machine, report); !errors.Is(err, ErrEnforcementUnavailable) {
		t.Fatalf("report without a recorder = %v", err)
	}
	recorded, err := service.WithEnforcementRecorder(&recordingEnforcementRecorder{})
	if err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string]ClientEnforcement{
		"no filter":   {NodeKey: initial.NodeKey(), AppliedAt: time.Now()},
		"no time":     {NodeKey: initial.NodeKey(), Filter: filter},
		"no node key": {Filter: filter, AppliedAt: time.Now()},
	} {
		if err := recorded.ReportEnforcement(t.Context(), machine, invalid); err == nil ||
			errors.Is(err, ErrNoEnforcementStream) {
			t.Errorf("%s: error = %v, want a validation error", name, err)
		}
	}
	if _, err := service.WithEnforcementRecorder(nil); !errors.Is(err, ErrInvalidStreamService) {
		t.Fatalf("WithEnforcementRecorder(nil) error = %v", err)
	}
	if _, err := NewFilterDigest(policydigest.Digest{}, 0); !errors.Is(err, ErrInvalidEnforcementReport) {
		t.Fatalf("NewFilterDigest(zero) error = %v", err)
	}
}

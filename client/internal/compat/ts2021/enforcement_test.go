package ts2021

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"tailscale.com/types/key"

	"meshtransit.net/shared/policydigest"
)

func testEnforcementReport(t *testing.T) EnforcementReport {
	t.Helper()
	digest, grants, err := policydigest.Compute(nil)
	if err != nil {
		t.Fatal(err)
	}
	return EnforcementReport{Digest: digest, Grants: grants, AppliedAt: time.Now()}
}

type recordingEnforcementSender struct {
	mu    sync.Mutex
	sent  []time.Time
	fails []error
}

func (sender *recordingEnforcementSender) send(context.Context, EnforcementReport) error {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	sender.sent = append(sender.sent, time.Now())
	if len(sender.fails) > 0 {
		err := sender.fails[0]
		sender.fails = sender.fails[1:]
		return err
	}
	return nil
}

func (sender *recordingEnforcementSender) count() int {
	sender.mu.Lock()
	defer sender.mu.Unlock()
	return len(sender.sent)
}

func TestEnforcementLoopConfirmsThenRepeats(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reports := make(chan EnforcementReport, 1)
		sender := &recordingEnforcementSender{}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			runEnforcementLoop(ctx, reports, sender.send)
			close(done)
		}()
		synctest.Wait()
		if sender.count() != 0 {
			t.Fatal("the loop sent before any report")
		}
		reports <- testEnforcementReport(t)
		synctest.Wait()
		if sender.count() != 1 {
			t.Fatalf("sent %d reports, want 1", sender.count())
		}
		time.Sleep(enforcementConfirm)
		synctest.Wait()
		if sender.count() != 2 {
			t.Fatalf("confirmation: sent %d, want 2", sender.count())
		}
		time.Sleep(enforcementHeartbeat)
		synctest.Wait()
		if sender.count() != 3 {
			t.Fatalf("heartbeat: sent %d, want 3", sender.count())
		}
		cancel()
		<-done
	})
}

func TestEnforcementLoopRetriesAndBacksOff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reports := make(chan EnforcementReport, 1)
		sender := &recordingEnforcementSender{fails: []error{
			ErrEnforcementReport, errEnforcementUnsupported,
		}}
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			runEnforcementLoop(ctx, reports, sender.send)
			close(done)
		}()
		reports <- testEnforcementReport(t)
		synctest.Wait()
		time.Sleep(enforcementRetryMaximum)
		synctest.Wait()
		if sender.count() != 2 {
			t.Fatalf("after a retryable failure sent %d, want 2", sender.count())
		}
		time.Sleep(enforcementHeartbeat)
		synctest.Wait()
		if sender.count() != 2 {
			t.Fatal("an unsupported Core was asked again before the long delay")
		}
		// A new report is sent at once, whatever the schedule.
		reports <- testEnforcementReport(t)
		synctest.Wait()
		if sender.count() != 3 {
			t.Fatalf("a new report was not sent at once: %d", sender.count())
		}
		cancel()
		<-done
	})
}

func TestEncodeEnforcementReport(t *testing.T) {
	report := testEnforcementReport(t)
	nodeKey := key.NewNode().Public()
	encoded, err := encodeEnforcementReport(nodeKey, report)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(encoded, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["version"] != float64(1) || wire["node_key"] != nodeKey.String() ||
		wire["digest"] != report.Digest.String() || len(wire) != 5 {
		t.Fatalf("wire = %v", wire)
	}
	if _, err := encodeEnforcementReport(nodeKey, EnforcementReport{}); !errors.Is(err, ErrEnforcementReport) {
		t.Fatalf("empty report error = %v", err)
	}
	for status, want := range map[int]error{
		http.StatusNoContent:          nil,
		http.StatusNotFound:           errEnforcementUnsupported,
		http.StatusBadRequest:         errEnforcementRefused,
		http.StatusConflict:           ErrEnforcementReport,
		http.StatusServiceUnavailable: ErrEnforcementReport,
	} {
		if err := classifyEnforcementStatus(status); !errors.Is(err, want) || (want == nil && err != nil) {
			t.Errorf("status %d: error = %v, want %v", status, err, want)
		}
	}
}

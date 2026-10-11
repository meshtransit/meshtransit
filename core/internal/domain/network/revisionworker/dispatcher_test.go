package revisionworker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/platform/observability"
)

func TestNewRejectsInvalidInputs(t *testing.T) {
	t.Parallel()

	validOptions := testOptions()
	outbox := &fakeOutbox{}
	publisher := &fakePublisher{}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	var nilOutbox *fakeOutbox
	var nilPublisher *fakePublisher

	tests := []struct {
		name      string
		options   Options
		outbox    Outbox
		publisher Publisher
		logger    *slog.Logger
	}{
		{name: "missing worker identity", options: replaceWorkerID(validOptions, ""), outbox: outbox, publisher: publisher, logger: logger},
		{name: "unsafe worker identity", options: replaceWorkerID(validOptions, "revision worker"), outbox: outbox, publisher: publisher, logger: logger},
		{name: "zero batch", options: replaceBatchSize(validOptions, 0), outbox: outbox, publisher: publisher, logger: logger},
		{name: "oversized batch", options: replaceBatchSize(validOptions, maxBatchSize+1), outbox: outbox, publisher: publisher, logger: logger},
		{name: "lease cannot cover batch", options: replaceLease(validOptions, 3*time.Second), outbox: outbox, publisher: publisher, logger: logger},
		{name: "missing outbox", options: validOptions, publisher: publisher, logger: logger},
		{name: "typed nil outbox", options: validOptions, outbox: nilOutbox, publisher: publisher, logger: logger},
		{name: "missing publisher", options: validOptions, outbox: outbox, logger: logger},
		{name: "typed nil publisher", options: validOptions, outbox: outbox, publisher: nilPublisher, logger: logger},
		{name: "missing telemetry", options: validOptions, outbox: outbox, publisher: publisher, logger: logger},
		{name: "missing logger", options: validOptions, outbox: outbox, publisher: publisher},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			telemetry := NewTelemetry()
			if test.name == "missing telemetry" {
				telemetry = nil
			}
			dispatcher, err := New(test.options, test.outbox, test.publisher, telemetry, test.logger)
			if !errors.Is(err, ErrInvalidDispatcher) {
				t.Fatalf("New() error = %v, want ErrInvalidDispatcher", err)
			}
			if dispatcher != nil {
				t.Fatalf("New() = %v, want nil", dispatcher)
			}
		})
	}
}

func TestDispatchOncePublishesThenMarksDelivered(t *testing.T) {
	t.Parallel()

	claim := testClaim(t)
	revision := testRevision(t)
	var calls []string
	outbox := &fakeOutbox{
		claim: func(_ context.Context, workerID string, limit int, lease time.Duration) ([]network.RevisionClaim, error) {
			calls = append(calls, "claim")
			options := testOptions()
			if workerID != options.WorkerID || limit != options.BatchSize || lease != options.Lease {
				t.Fatalf(
					"claim arguments = (%q, %d, %s), want (%q, %d, %s)",
					workerID,
					limit,
					lease,
					options.WorkerID,
					options.BatchSize,
					options.Lease,
				)
			}
			return []network.RevisionClaim{claim}, nil
		},
		load: func(context.Context, network.RevisionClaim) (network.RevisionAdvanced, error) {
			calls = append(calls, "load")
			return revision, nil
		},
		mark: func(context.Context, network.RevisionClaim) error {
			calls = append(calls, "mark")
			return nil
		},
	}
	publisher := &fakePublisher{publish: func(context.Context, network.RevisionAdvanced) error {
		calls = append(calls, "publish")
		return nil
	}}
	dispatcher := mustDispatcher(t, outbox, publisher, io.Discard)

	if _, err := dispatcher.dispatchOnce(t.Context()); err != nil {
		t.Fatalf("dispatchOnce() error = %v", err)
	}
	if got, want := strings.Join(calls, ","), "claim,load,publish,mark"; got != want {
		t.Fatalf("call order = %q, want %q", got, want)
	}
	snapshot := dispatcher.telemetry.Snapshot()
	if snapshot.BacklogSuccessTotal != 1 || snapshot.ClaimSuccessTotal != 1 ||
		snapshot.ClaimedEventsTotal != 1 || snapshot.DeliveredTotal != 1 {
		t.Fatalf("unexpected successful dispatch telemetry: %+v", snapshot)
	}
}

func TestDispatchOnceContinuesWhenBacklogObservationFails(t *testing.T) {
	t.Parallel()

	observationErr := errors.New("backlog unavailable")
	claimed := false
	outbox := &fakeOutbox{
		backlog: func(context.Context) (Backlog, error) {
			return Backlog{}, observationErr
		},
		claim: func(context.Context, string, int, time.Duration) ([]network.RevisionClaim, error) {
			claimed = true
			return nil, nil
		},
	}
	dispatcher := mustDispatcher(t, outbox, &fakePublisher{}, io.Discard)

	_, err := dispatcher.dispatchOnce(t.Context())
	if !errors.Is(err, observationErr) {
		t.Fatalf("dispatchOnce() error = %v, want backlog observation error", err)
	}
	if !claimed {
		t.Fatal("dispatchOnce() did not claim after a metrics-only query failed")
	}
	snapshot := dispatcher.telemetry.Snapshot()
	if snapshot.BacklogErrorTotal != 1 || snapshot.ClaimSuccessTotal != 1 {
		t.Fatalf("unexpected degraded dispatch telemetry: %+v", snapshot)
	}
}

func TestDispatchOnceReturnsRetryPersistenceFailure(t *testing.T) {
	t.Parallel()

	deliveryErr := errors.New("publish unavailable")
	retryErr := errors.New("retry persistence unavailable")
	claim := testClaim(t)
	outbox := &fakeOutbox{
		claim: func(context.Context, string, int, time.Duration) ([]network.RevisionClaim, error) {
			return []network.RevisionClaim{claim}, nil
		},
		load: func(context.Context, network.RevisionClaim) (network.RevisionAdvanced, error) {
			return testRevision(t), nil
		},
		retry: func(context.Context, network.RevisionClaim, string, time.Duration) error {
			return retryErr
		},
	}
	publisher := &fakePublisher{publish: func(context.Context, network.RevisionAdvanced) error {
		return deliveryErr
	}}
	dispatcher := mustDispatcher(t, outbox, publisher, io.Discard)

	_, err := dispatcher.dispatchOnce(t.Context())
	if !errors.Is(err, deliveryErr) || !errors.Is(err, retryErr) {
		t.Fatalf("dispatchOnce() error = %v, want delivery and retry persistence failures", err)
	}
}

func TestDispatchOnceDefersRetryWithoutExposingFailure(t *testing.T) {
	t.Parallel()

	secretFailure := errors.New("private dependency detail")
	tests := []struct {
		name           string
		loadError      error
		publishError   error
		wantErrorClass string
	}{
		{name: "load failure", loadError: secretFailure, wantErrorClass: errorClassLoadRevision},
		{name: "publish failure", publishError: secretFailure, wantErrorClass: errorClassPublishWakeup},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			claim := testClaim(t)
			revision := testRevision(t)
			var gotClass string
			var gotDelay time.Duration
			outbox := &fakeOutbox{
				claim: func(context.Context, string, int, time.Duration) ([]network.RevisionClaim, error) {
					return []network.RevisionClaim{claim}, nil
				},
				load: func(context.Context, network.RevisionClaim) (network.RevisionAdvanced, error) {
					return revision, test.loadError
				},
				retry: func(_ context.Context, _ network.RevisionClaim, errorClass string, delay time.Duration) error {
					gotClass = errorClass
					gotDelay = delay
					return nil
				},
			}
			publisher := &fakePublisher{publish: func(context.Context, network.RevisionAdvanced) error {
				return test.publishError
			}}
			var logs bytes.Buffer
			dispatcher := mustDispatcher(t, outbox, publisher, &logs)

			if _, err := dispatcher.dispatchOnce(t.Context()); err != nil {
				t.Fatalf("dispatchOnce() error = %v", err)
			}
			if gotClass != test.wantErrorClass || gotDelay != testOptions().RetryDelay {
				t.Fatalf("retry = (%q, %s), want (%q, %s)", gotClass, gotDelay, test.wantErrorClass, testOptions().RetryDelay)
			}
			if strings.Contains(logs.String(), secretFailure.Error()) || !strings.Contains(logs.String(), `"error":"[REDACTED]"`) {
				t.Fatalf("log did not redact failure detail: %s", logs.String())
			}
		})
	}
}

func TestDispatchOnceLeavesPublishedClaimForLeaseRecoveryWhenCompletionFails(t *testing.T) {
	t.Parallel()

	markErr := errors.New("completion unavailable")
	claim := testClaim(t)
	outbox := &fakeOutbox{
		claim: func(context.Context, string, int, time.Duration) ([]network.RevisionClaim, error) {
			return []network.RevisionClaim{claim}, nil
		},
		load: func(context.Context, network.RevisionClaim) (network.RevisionAdvanced, error) {
			return testRevision(t), nil
		},
		mark: func(context.Context, network.RevisionClaim) error { return markErr },
		retry: func(context.Context, network.RevisionClaim, string, time.Duration) error {
			t.Fatal("RetryNetworkRevision() called after a successful publish")
			return nil
		},
	}
	dispatcher := mustDispatcher(t, outbox, &fakePublisher{}, io.Discard)

	_, err := dispatcher.dispatchOnce(t.Context())
	if !errors.Is(err, markErr) {
		t.Fatalf("dispatchOnce() error = %v, want mark error", err)
	}
}

func TestDispatchOnceRejectsOversizedAdapterBatch(t *testing.T) {
	t.Parallel()

	claim := testClaim(t)
	outbox := &fakeOutbox{claim: func(context.Context, string, int, time.Duration) ([]network.RevisionClaim, error) {
		return []network.RevisionClaim{claim, claim}, nil
	}}
	dispatcher := mustDispatcher(t, outbox, &fakePublisher{}, io.Discard)
	dispatcher.options.BatchSize = 1
	dispatcher.options.Lease = 4 * time.Second

	_, err := dispatcher.dispatchOnce(t.Context())
	if !errors.Is(err, ErrInvalidClaimBatch) {
		t.Fatalf("dispatchOnce() error = %v, want ErrInvalidClaimBatch", err)
	}
}

func TestDispatchOnceBoundsOutboxClaim(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		outbox := &fakeOutbox{claim: func(ctx context.Context, _ string, _ int, _ time.Duration) ([]network.RevisionClaim, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}}
		dispatcher := mustDispatcher(t, outbox, &fakePublisher{}, io.Discard)

		started := time.Now()
		_, err := dispatcher.dispatchOnce(t.Context())
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("dispatchOnce() error = %v, want context deadline exceeded", err)
		}
		if elapsed := time.Since(started); elapsed != testOptions().OperationTimeout {
			t.Fatalf("claim elapsed = %s, want %s", elapsed, testOptions().OperationTimeout)
		}
	})
}

func TestDispatcherShutdownCancelsInFlightWorkAndJoins(t *testing.T) {
	t.Parallel()

	claimStarted := make(chan struct{})
	claimCanceled := make(chan struct{})
	var startOnce sync.Once
	var cancelOnce sync.Once
	outbox := &fakeOutbox{claim: func(ctx context.Context, _ string, _ int, _ time.Duration) ([]network.RevisionClaim, error) {
		startOnce.Do(func() { close(claimStarted) })
		<-ctx.Done()
		cancelOnce.Do(func() { close(claimCanceled) })
		return nil, ctx.Err()
	}}
	dispatcher := mustDispatcher(t, outbox, &fakePublisher{}, io.Discard)

	if err := dispatcher.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	<-claimStarted
	if err := dispatcher.Start(t.Context()); !errors.Is(err, ErrDispatcherStarted) {
		t.Fatalf("second Start() error = %v, want ErrDispatcherStarted", err)
	}
	if err := dispatcher.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	<-claimCanceled
	if err := <-dispatcher.Done(); err != nil {
		t.Fatalf("Done() error = %v", err)
	}
}

func TestDispatcherRejectsShutdownBeforeStart(t *testing.T) {
	t.Parallel()

	dispatcher := mustDispatcher(t, &fakeOutbox{}, &fakePublisher{}, io.Discard)
	if err := dispatcher.Shutdown(t.Context()); !errors.Is(err, ErrDispatcherNotStarted) {
		t.Fatalf("Shutdown() error = %v, want ErrDispatcherNotStarted", err)
	}
	if dispatcher.Done() != nil {
		t.Fatal("Done() != nil before Start()")
	}
}

func TestDispatcherRejectsCanceledStartWithoutLaunchingWorker(t *testing.T) {
	t.Parallel()

	dispatcher := mustDispatcher(t, &fakeOutbox{}, &fakePublisher{}, io.Discard)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := dispatcher.Start(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Start() error = %v, want context canceled", err)
	}
	if dispatcher.Done() != nil {
		t.Fatal("Done() != nil after canceled startup")
	}
}

func testOptions() Options {
	return Options{
		WorkerID:         "revision-worker",
		BatchSize:        1,
		Lease:            5 * time.Second,
		PollInterval:     time.Second,
		RetryDelay:       time.Second,
		OperationTimeout: time.Second,
	}
}

func replaceWorkerID(options Options, workerID string) Options {
	options.WorkerID = workerID
	return options
}

func replaceBatchSize(options Options, batchSize int) Options {
	options.BatchSize = batchSize
	return options
}

func replaceLease(options Options, lease time.Duration) Options {
	options.Lease = lease
	return options
}

func mustDispatcher(t *testing.T, outbox Outbox, publisher Publisher, output io.Writer) *Dispatcher {
	t.Helper()

	logger, err := observability.NewLogger(output, slog.LevelDebug)
	if err != nil {
		t.Fatalf("observability.NewLogger() error = %v", err)
	}
	dispatcher, err := New(testOptions(), outbox, publisher, NewTelemetry(), logger)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return dispatcher
}

func testClaim(t *testing.T) network.RevisionClaim {
	t.Helper()

	claim, err := network.NewRevisionClaim(
		1,
		2,
		3,
		4,
		"01890f5e-7b9a-7123-8abc-1234567890ab",
		"revision-worker",
		1,
		time.Unix(1, 0).UTC(),
	)
	if err != nil {
		t.Fatalf("network.NewRevisionClaim() error = %v", err)
	}
	return claim
}

func testRevision(t *testing.T) network.RevisionAdvanced {
	t.Helper()

	revision, err := network.NewRevisionAdvanced("01890f5e-7b9a-7123-8abc-1234567890ab", 5)
	if err != nil {
		t.Fatalf("network.NewRevisionAdvanced() error = %v", err)
	}
	return revision
}

type fakeOutbox struct {
	backlog func(context.Context) (Backlog, error)
	claim   func(context.Context, string, int, time.Duration) ([]network.RevisionClaim, error)
	load    func(context.Context, network.RevisionClaim) (network.RevisionAdvanced, error)
	mark    func(context.Context, network.RevisionClaim) error
	retry   func(context.Context, network.RevisionClaim, string, time.Duration) error
}

func (outbox *fakeOutbox) ReadNetworkRevisionBacklog(ctx context.Context) (Backlog, error) {
	if outbox.backlog == nil {
		return NewBacklog(0, 0)
	}
	return outbox.backlog(ctx)
}

func (outbox *fakeOutbox) ClaimNetworkRevisions(
	ctx context.Context,
	workerID string,
	limit int,
	lease time.Duration,
) ([]network.RevisionClaim, error) {
	if outbox.claim == nil {
		return nil, nil
	}
	return outbox.claim(ctx, workerID, limit, lease)
}

func (outbox *fakeOutbox) LoadNetworkRevision(
	ctx context.Context,
	claim network.RevisionClaim,
) (network.RevisionAdvanced, error) {
	if outbox.load == nil {
		return network.RevisionAdvanced{}, nil
	}
	return outbox.load(ctx, claim)
}

func (outbox *fakeOutbox) MarkRevisionDelivered(
	ctx context.Context,
	claim network.RevisionClaim,
) error {
	if outbox.mark == nil {
		return nil
	}
	return outbox.mark(ctx, claim)
}

func (outbox *fakeOutbox) RetryNetworkRevision(
	ctx context.Context,
	claim network.RevisionClaim,
	errorClass string,
	retryDelay time.Duration,
) error {
	if outbox.retry == nil {
		return nil
	}
	return outbox.retry(ctx, claim, errorClass, retryDelay)
}

type fakePublisher struct {
	publish func(context.Context, network.RevisionAdvanced) error
}

func (publisher *fakePublisher) PublishNetworkRevisionAdvanced(
	ctx context.Context,
	revision network.RevisionAdvanced,
) error {
	if publisher.publish == nil {
		return nil
	}
	return publisher.publish(ctx, revision)
}

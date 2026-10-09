package endpointpublication

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/sharing"
)

const (
	minimumPollInterval     = 100 * time.Millisecond
	maximumPollInterval     = time.Minute
	minimumOperationTimeout = 100 * time.Millisecond
	maximumOperationTimeout = 30 * time.Second
	minimumRetryDelay       = 100 * time.Millisecond
	maximumRetryDelay       = time.Hour
	maximumBatchSize        = 128
	publicationRetryPrefix  = "publish:"
	withdrawalRetryPrefix   = "withdraw:"
)

var (
	// ErrInvalidWorker reports incomplete dependencies or unsafe work bounds.
	ErrInvalidWorker = errors.New("private endpoint publication: invalid worker")
	// ErrWorkerStarted reports duplicate lifecycle ownership.
	ErrWorkerStarted = errors.New("private endpoint publication: worker already started")
	// ErrWorkerNotStarted reports shutdown before successful startup.
	ErrWorkerNotStarted = errors.New("private endpoint publication: worker not started")
)

// Options binds one worker process to an exact Deployment and finite work.
type Options struct {
	DeploymentID      deployment.ID
	ReconcilerID      string
	BatchSize         int
	PollInterval      time.Duration
	OperationTimeout  time.Duration
	InitialRetryDelay time.Duration
	MaximumRetryDelay time.Duration
}

// Worker owns one sequential reconciliation goroutine. Withdrawal is always
// processed before publication so a cycle closes stale authority first.
type Worker struct {
	options   Options
	store     Store
	gateway   Gateway
	telemetry *Telemetry
	logger    *slog.Logger
	clock     func() time.Time

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan error
	retries map[string]retryState
}

type retryState struct {
	failures uint8
	next     time.Time
}

// New constructs a stopped worker without performing I/O.
func New(options Options, store Store, gateway Gateway, telemetry *Telemetry, logger *slog.Logger) (*Worker, error) {
	worker := &Worker{
		options: options, store: store, gateway: gateway, telemetry: telemetry,
		logger: logger, clock: func() time.Time { return time.Now().UTC() }, retries: make(map[string]retryState),
	}
	if !worker.valid() {
		return nil, ErrInvalidWorker
	}
	return worker, nil
}

func (worker *Worker) valid() bool {
	if worker == nil || !worker.options.DeploymentID.IsValid() ||
		!validReconcilerID(worker.options.ReconcilerID) || worker.options.BatchSize < 1 ||
		worker.options.BatchSize > maximumBatchSize || worker.options.PollInterval < minimumPollInterval ||
		worker.options.PollInterval > maximumPollInterval ||
		worker.options.OperationTimeout < minimumOperationTimeout ||
		worker.options.OperationTimeout > maximumOperationTimeout ||
		worker.options.InitialRetryDelay < minimumRetryDelay ||
		worker.options.MaximumRetryDelay < worker.options.InitialRetryDelay ||
		worker.options.MaximumRetryDelay > maximumRetryDelay || worker.telemetry == nil ||
		worker.logger == nil || worker.clock == nil {
		return false
	}
	return !nilPort(worker.store) && !nilPort(worker.gateway)
}

func validReconcilerID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || character == '.' || character == '_' ||
			character == ':' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func nilPort(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// Start starts exactly one process-owned goroutine.
func (worker *Worker) Start(ctx context.Context) error {
	if ctx == nil || !worker.valid() {
		return ErrInvalidWorker
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if worker.started {
		return ErrWorkerStarted
	}
	owned, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan error, 1)
	worker.cancel, worker.done, worker.started = cancel, done, true
	go func() {
		worker.telemetry.setRunning(true)
		err := worker.run(owned)
		worker.telemetry.setRunning(false)
		done <- err
		close(done)
	}()
	return nil
}

// Done returns the lifecycle join channel after Start.
func (worker *Worker) Done() <-chan error {
	if worker == nil {
		return nil
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	return worker.done
}

// Shutdown signals cancellation; Done remains the owned join path.
func (worker *Worker) Shutdown(ctx context.Context) error {
	if ctx == nil || !worker.valid() {
		return ErrInvalidWorker
	}
	worker.mu.Lock()
	if !worker.started {
		worker.mu.Unlock()
		return ErrWorkerNotStarted
	}
	cancel := worker.cancel
	worker.mu.Unlock()
	cancel()
	return nil
}

func (worker *Worker) run(ctx context.Context) error {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			worker.reconcile(ctx)
			if ctx.Err() != nil {
				return nil
			}
			timer.Reset(worker.options.PollInterval)
		}
	}
}

func (worker *Worker) reconcile(ctx context.Context) {
	worker.telemetry.recordPass()
	withdrawalsComplete := worker.reconcileWithdrawals(ctx)
	if withdrawalsComplete && ctx.Err() == nil {
		worker.reconcilePublications(ctx)
	}
}

func (worker *Worker) reconcileWithdrawals(ctx context.Context) bool {
	candidates, err := worker.listWithdrawals(ctx)
	worker.telemetry.observeCandidates(operationWithdrawal, len(candidates), err)
	if err != nil {
		worker.logFailure(ctx, "private_endpoint_withdrawal_list_failed")
		return false
	}
	worker.retainRetries(withdrawalRetryPrefix, candidates)
	complete := true
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return false
		}
		key := withdrawalRetryPrefix + candidate.EndpointID.String()
		if !candidate.IsValid() {
			complete = false
			worker.logFailure(ctx, "private_endpoint_withdrawal_candidate_invalid")
			continue
		}
		if !worker.retryReady(key) {
			complete = false
			continue
		}
		if err := worker.withdraw(ctx, candidate); err != nil {
			complete = false
			worker.deferRetry(key)
			worker.telemetry.recordAttempt(operationWithdrawal, resultDeferred)
			worker.logFailure(ctx, "private_endpoint_withdrawal_deferred")
			continue
		}
		worker.clearRetry(key)
		worker.telemetry.recordAttempt(operationWithdrawal, resultSucceeded)
	}
	return complete
}

func (worker *Worker) withdraw(ctx context.Context, candidate Candidate) error {
	snapshot, err := worker.readWithdrawal(ctx, candidate.EndpointID)
	if err != nil {
		return err
	}
	command, err := snapshot.Withdrawal()
	if err != nil {
		return err
	}
	hash, err := snapshot.TerminalHash()
	if err != nil {
		return err
	}
	if snapshot.RoutePresent {
		if err := worker.gatewayWithdraw(ctx, command, hash); err != nil {
			return err
		}
	}
	return worker.finalizeWithdrawal(ctx, snapshot, hash)
}

func (worker *Worker) reconcilePublications(ctx context.Context) {
	candidates, err := worker.listPublications(ctx)
	worker.telemetry.observeCandidates(operationPublication, len(candidates), err)
	if err != nil {
		worker.logFailure(ctx, "private_endpoint_publication_list_failed")
		return
	}
	worker.retainRetries(publicationRetryPrefix, candidates)
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return
		}
		key := publicationRetryPrefix + candidate.EndpointID.String()
		if !candidate.IsValid() || !worker.retryReady(key) {
			continue
		}
		if err := worker.publish(ctx, candidate); err != nil {
			worker.deferRetry(key)
			worker.telemetry.recordAttempt(operationPublication, resultDeferred)
			worker.logFailure(ctx, "private_endpoint_publication_deferred")
			continue
		}
		worker.clearRetry(key)
		worker.telemetry.recordAttempt(operationPublication, resultSucceeded)
	}
}

func (worker *Worker) publish(ctx context.Context, candidate Candidate) error {
	snapshot, err := worker.readPublication(ctx, candidate.EndpointID)
	if err != nil {
		return err
	}
	route, err := snapshot.Route()
	if err != nil {
		return err
	}
	hash, err := route.Hash()
	if err != nil {
		return err
	}
	if err := worker.stagePublication(ctx, snapshot, hash); err != nil {
		return err
	}
	if err := worker.gatewayApply(ctx, route, hash); err != nil {
		return err
	}
	if err := worker.confirmPublication(ctx, snapshot, hash); err != nil {
		// A route without committed DNS/readiness authority must not remain
		// reachable. Best-effort compensation is retried by gateway idempotency.
		withdrawal := Withdrawal{
			DeploymentID: route.DeploymentID, EndpointID: route.EndpointID,
			EndpointGeneration: route.EndpointGeneration, ResourceAlias: route.ResourceAlias,
			RouteSnapshotHash: hex.EncodeToString(hash[:]), RoutePresent: true,
			Reason: string(WithdrawalInvalidated),
		}
		compensationHash, hashErr := withdrawal.Hash()
		if hashErr == nil {
			_ = worker.gatewayWithdraw(ctx, withdrawal, compensationHash)
		}
		return err
	}
	return nil
}

func (worker *Worker) stagePublication(ctx context.Context, snapshot Snapshot, hash [32]byte) error {
	operationCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	return worker.store.StagePublication(operationCtx, snapshot, hash, worker.options.ReconcilerID)
}

func (worker *Worker) listWithdrawals(ctx context.Context) ([]Candidate, error) {
	operationCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	return worker.store.ListWithdrawalCandidates(operationCtx, worker.options.DeploymentID, worker.options.BatchSize)
}

func (worker *Worker) listPublications(ctx context.Context) ([]Candidate, error) {
	operationCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	return worker.store.ListPublicationCandidates(operationCtx, worker.options.DeploymentID, worker.options.BatchSize)
}

func (worker *Worker) readWithdrawal(ctx context.Context, id sharing.PrivateEndpointID) (WithdrawalSnapshot, error) {
	operationCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	return worker.store.ReadWithdrawalSnapshot(operationCtx, worker.options.DeploymentID, id)
}

func (worker *Worker) readPublication(ctx context.Context, id sharing.PrivateEndpointID) (Snapshot, error) {
	operationCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	return worker.store.ReadPublicationSnapshot(operationCtx, worker.options.DeploymentID, id)
}

func (worker *Worker) gatewayApply(ctx context.Context, route Route, hash [32]byte) error {
	operationCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	return worker.gateway.Apply(operationCtx, route, hash)
}

func (worker *Worker) gatewayWithdraw(ctx context.Context, command Withdrawal, hash [32]byte) error {
	operationCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	return worker.gateway.Withdraw(operationCtx, command, hash)
}

func (worker *Worker) confirmPublication(ctx context.Context, snapshot Snapshot, hash [32]byte) error {
	operationCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	return worker.store.ConfirmPublication(operationCtx, snapshot, hash, worker.options.ReconcilerID)
}

func (worker *Worker) finalizeWithdrawal(ctx context.Context, snapshot WithdrawalSnapshot, hash [32]byte) error {
	operationCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	return worker.store.FinalizeWithdrawal(operationCtx, snapshot, hash, worker.options.ReconcilerID)
}

func (worker *Worker) retryReady(key string) bool {
	retry, found := worker.retries[key]
	return !found || !worker.clock().Before(retry.next)
}

func (worker *Worker) deferRetry(key string) {
	retry := worker.retries[key]
	if retry.failures < 63 {
		retry.failures++
	}
	delay := worker.options.InitialRetryDelay
	for range max(0, int(retry.failures)-1) {
		if delay >= worker.options.MaximumRetryDelay/2 {
			delay = worker.options.MaximumRetryDelay
			break
		}
		delay *= 2
	}
	retry.next = worker.clock().Add(min(delay, worker.options.MaximumRetryDelay))
	worker.retries[key] = retry
}

func (worker *Worker) clearRetry(key string) { delete(worker.retries, key) }

func (worker *Worker) retainRetries(prefix string, candidates []Candidate) {
	active := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		active[prefix+candidate.EndpointID.String()] = struct{}{}
	}
	for key := range worker.retries {
		if strings.HasPrefix(key, prefix) {
			if _, found := active[key]; !found {
				delete(worker.retries, key)
			}
		}
	}
}

func (worker *Worker) logFailure(ctx context.Context, code string) {
	worker.logger.WarnContext(ctx, "private endpoint reconciliation deferred", "error_code", code)
}

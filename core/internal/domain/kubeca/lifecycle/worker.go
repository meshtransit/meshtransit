package lifecycle

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	maximumBatchSize = 64
	// custodyRetry is how often the worker reads its custody's keys again:
	// a new wrap key file is picked up within a minute.
	custodyRetry = time.Minute
	// maximumRetryDelay caps the backoff of a Network that keeps failing.
	maximumRetryDelay = time.Hour
	// Capability names what this worker does, for control to read (§17.3).
	Capability = "ca.lifecycle1"
)

var (
	// ErrInvalidWorker rejects unsafe dependencies or timing bounds.
	ErrInvalidWorker = errors.New("kubernetes CA worker: invalid configuration")
	// ErrWorkerStarted rejects duplicate lifecycle ownership.
	ErrWorkerStarted = errors.New("kubernetes CA worker: already started")
	// ErrWorkerNotStarted rejects shutdown before startup.
	ErrWorkerNotStarted = errors.New("kubernetes CA worker: not started")
	// ErrBusy reports a Network another worker or operator holds: nothing
	// was applied; try again.
	ErrBusy      = errors.New("kubernetes CA lifecycle: the Network is busy")
	errNoCustody = errors.New("kubernetes CA worker: no custody")
	// errClustersFailed reports a Network some of whose clusters failed
	// alone and were scheduled again one by one.
	errClustersFailed = errors.New("kubernetes CA worker: some clusters failed")
)

// Store is the worker's view of the stored CAs (the postgres adapter).
type Store interface {
	ListDue(ctx context.Context, installation deployment.ID, limit int) ([]network.Scope, error)
	ClaimDNSSuffix(ctx context.Context, installation deployment.ID, suffix string) (string, bool, error)
	Read(ctx context.Context, installation deployment.ID, scope network.Scope) (kubeca.Network, error)
	Change(ctx context.Context, installation deployment.ID, scope network.Scope,
		plan func(kubeca.Network) (kubeca.Changes, error)) (bool, error)
	AddDataKey(ctx context.Context, installation deployment.ID, scope network.Scope, id publicid.ID,
		wrapped kubeca.WrappedKey, operator kubeca.Operator) (bool, error)
	Postpone(ctx context.Context, installation deployment.ID, scope network.Scope, until time.Time) (bool, error)
	Beat(ctx context.Context, installation deployment.ID, instance publicid.ID, ready bool, version, custody string,
		capabilities []string) (time.Time, error)
}

// CustodySource builds the worker's custody, reading its keys: it may fail
// at start (a missing key file) and is tried again every minute, while the
// worker keeps beating without it (§13 N8).
type CustodySource func(ctx context.Context) (kubeca.Custody, string, error)

// Options binds the worker to its installation, DNS suffix and pace.
type Options struct {
	DeploymentID     deployment.ID
	Suffix           dnsname.Suffix
	BatchSize        int
	PollInterval     time.Duration
	OperationTimeout time.Duration
	Version          string
	Policy           Policy
}

func (options Options) valid() bool {
	return options.DeploymentID.IsValid() && options.Suffix.IsValid() && options.BatchSize >= 1 &&
		options.BatchSize <= maximumBatchSize && options.PollInterval >= time.Second &&
		options.PollInterval <= 5*time.Minute && options.OperationTimeout >= time.Second &&
		options.OperationTimeout <= time.Minute && options.Version != "" && options.Policy.Valid()
}

// Measurements are identifier-free counts for metrics.
type Measurements struct {
	Running, CustodyReady, SuffixMismatch                     bool
	Passes, Networks, Changed, PlanChanged, Failures, Created uint64
	Moved, Misnamed, Busy                                     uint64
}

// Worker keeps the CAs of the installation's clusters through their life.
// It owns one goroutine.
type Worker struct {
	options  Options
	store    Store
	source   CustodySource
	logger   *slog.Logger
	instance publicid.ID

	// Owned by the worker goroutine.
	custody      kubeca.Custody
	custodyKind  string
	custodyTried time.Time
	backoff      map[network.Scope]retryState

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan error

	running, custodyReady, suffixMismatch                   atomic.Bool
	passes, networks, changed, planChanged, failures, moved atomic.Uint64
	created, misnamed, busy                                 atomic.Uint64
}

type retryState struct {
	failures int
	until    time.Time
}

// New builds a stopped worker without I/O.
func New(options Options, store Store, source CustodySource, logger *slog.Logger) (*Worker, error) {
	if !options.valid() || store == nil || source == nil || logger == nil {
		return nil, ErrInvalidWorker
	}
	instance, err := publicid.New()
	if err != nil {
		return nil, err
	}
	return &Worker{
		options: options, store: store, source: source, logger: logger, instance: instance,
		backoff: map[network.Scope]retryState{},
	}, nil
}

// Start owns cancellation separately from the caller's startup context.
func (worker *Worker) Start(ctx context.Context) error {
	if worker == nil || ctx == nil {
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
	worker.cancel, worker.done, worker.started = cancel, make(chan error, 1), true
	go func() {
		worker.running.Store(true)
		worker.run(owned)
		worker.running.Store(false)
		worker.done <- nil
		close(worker.done)
	}()
	return nil
}

// Done is the process-owned lifecycle join, available after Start.
func (worker *Worker) Done() <-chan error {
	if worker == nil {
		return nil
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	return worker.done
}

// Shutdown cancels the worker's work; Done is the join.
func (worker *Worker) Shutdown(ctx context.Context) error {
	if worker == nil || ctx == nil {
		return ErrInvalidWorker
	}
	worker.mu.Lock()
	defer worker.mu.Unlock()
	if !worker.started {
		return ErrWorkerNotStarted
	}
	worker.cancel()
	return nil
}

// Snapshot returns race-safe measurements without tenant identifiers.
func (worker *Worker) Snapshot() Measurements {
	if worker == nil {
		return Measurements{}
	}
	return Measurements{
		Running: worker.running.Load(), CustodyReady: worker.custodyReady.Load(),
		SuffixMismatch: worker.suffixMismatch.Load(), Passes: worker.passes.Load(), Networks: worker.networks.Load(),
		Changed: worker.changed.Load(), PlanChanged: worker.planChanged.Load(), Failures: worker.failures.Load(),
		Created: worker.created.Load(), Moved: worker.moved.Load(), Misnamed: worker.misnamed.Load(),
		Busy: worker.busy.Load(),
	}
}

func (worker *Worker) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			worker.Pass(ctx)
			if ctx.Err() != nil {
				return
			}
			timer.Reset(worker.options.PollInterval)
		}
	}
}

// Pass is one round: build the custody if missing, beat, check the
// suffix, and keep the CAs of the Networks due. Exported for tests.
func (worker *Worker) Pass(ctx context.Context) {
	worker.passes.Add(1)
	worker.loadCustody(ctx)
	worker.forgetStaleBackoff()
	worker.beat(ctx)
	if !worker.claimSuffix(ctx) {
		return
	}
	limit := min(maximumBatchSize, worker.options.BatchSize+len(worker.backoff))
	listCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	scopes, err := worker.store.ListDue(listCtx, worker.options.DeploymentID, limit)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			worker.logger.WarnContext(ctx, "kubernetes CA work deferred", "error_code", "kubernetes_ca_read_failed")
		}
		return
	}
	now := time.Now()
	attempted := 0
	for _, scope := range scopes {
		if ctx.Err() != nil || attempted == worker.options.BatchSize {
			return
		}
		if entry, waiting := worker.backoff[scope]; waiting && now.Before(entry.until) {
			continue
		}
		attempted++
		worker.networks.Add(1)
		operationCtx, stop := context.WithTimeout(ctx, worker.options.OperationTimeout)
		err := worker.keep(operationCtx, scope)
		stop()
		worker.settle(ctx, scope, err)
	}
}

// settle records how keeping a Network went: a failure backs it off and
// postpones it in the database, so it does not stay first in line.
func (worker *Worker) settle(ctx context.Context, scope network.Scope, err error) {
	switch {
	case err == nil:
		delete(worker.backoff, scope)
		worker.changed.Add(1)
		return
	case errors.Is(err, ErrPlanChanged):
		worker.planChanged.Add(1)
		return
	case errors.Is(err, ErrBusy):
		worker.busy.Add(1)
		return
	case errors.Is(err, errClustersFailed):
		// The failing clusters are scheduled again one by one; the others
		// went ahead.
		delete(worker.backoff, scope)
		worker.failures.Add(1)
		return
	}
	worker.failures.Add(1)
	entry := worker.backoff[scope]
	entry.failures++
	delay := worker.retryDelay(entry.failures)
	entry.until = time.Now().Add(delay)
	worker.backoff[scope] = entry
	worker.logger.WarnContext(ctx, "kubernetes CA change deferred", "error_code", errorCode(err),
		"failures", entry.failures)
	postponeCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	if _, postponeErr := worker.store.Postpone(postponeCtx, worker.options.DeploymentID, scope,
		time.Now().Add(delay)); postponeErr != nil && ctx.Err() == nil {
		worker.logger.WarnContext(ctx, "kubernetes CA postponement failed", "error_code", "kubernetes_ca_postpone_failed")
	}
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, errNoCustody):
		return "kubernetes_ca_custody_missing"
	case errors.Is(err, kubeca.ErrMisconfigured):
		return "kubernetes_ca_custody_misconfigured"
	case errors.Is(err, kubeca.ErrUnavailable):
		return "kubernetes_ca_custody_unavailable"
	case errors.Is(err, kubeca.ErrInvalid):
		return "kubernetes_ca_invalid"
	}
	return "kubernetes_ca_store_failed"
}

func (worker *Worker) retryDelay(failures int) time.Duration {
	delay := worker.options.PollInterval
	for range min(failures, 16) {
		delay *= 2
		if delay >= maximumRetryDelay {
			return maximumRetryDelay
		}
	}
	return delay
}

// loadCustody builds the custody again every minute, so a rotated wrap key
// file takes effect without a restart (review a2 M-A). A failed read keeps
// the custody it had.
func (worker *Worker) loadCustody(ctx context.Context) {
	if !worker.custodyTried.IsZero() && time.Since(worker.custodyTried) < custodyRetry {
		return
	}
	worker.custodyTried = time.Now()
	custody, kind, err := worker.source(ctx)
	if err != nil || custody == nil || kind == "" {
		if worker.custody == nil {
			worker.custodyReady.Store(false)
		}
		worker.logger.ErrorContext(ctx, "kubernetes CA custody unavailable", "error_code",
			"kubernetes_ca_custody_missing", "kept", worker.custody != nil)
		return
	}
	worker.custody, worker.custodyKind = custody, kind
	worker.custodyReady.Store(true)
}

// forgetStaleBackoff drops Networks no longer retried, so the map does not
// grow with Networks that went away (review a2 L-B).
func (worker *Worker) forgetStaleBackoff() {
	cutoff := time.Now().Add(-maximumRetryDelay)
	for scope, entry := range worker.backoff {
		if entry.until.Before(cutoff) {
			delete(worker.backoff, scope)
		}
	}
}

// beat tells control this worker is alive and what it does. It signs
// nothing yet, so it is never ready to sign (a3 adds signing).
func (worker *Worker) beat(ctx context.Context) {
	custody := worker.custodyKind
	if custody == "" {
		custody = "none"
	}
	beatCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	if _, err := worker.store.Beat(beatCtx, worker.options.DeploymentID, worker.instance, false, worker.options.Version,
		custody, []string{Capability}); err != nil && ctx.Err() == nil {
		worker.logger.WarnContext(ctx, "kubernetes CA heartbeat failed", "error_code", "kubernetes_ca_beat_failed")
	}
}

// claimSuffix checks the worker's suffix is the one the installation
// recorded: otherwise it names no cluster (§17.1 C2).
func (worker *Worker) claimSuffix(ctx context.Context) bool {
	claimCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	_, matched, err := worker.store.ClaimDNSSuffix(claimCtx, worker.options.DeploymentID,
		worker.options.Suffix.String())
	if err != nil {
		if ctx.Err() == nil {
			worker.logger.WarnContext(ctx, "kubernetes CA suffix check failed", "error_code", "kubernetes_ca_read_failed")
		}
		return false
	}
	worker.suffixMismatch.Store(!matched)
	if !matched {
		worker.logger.ErrorContext(ctx, "kubernetes CA work stopped: the DNS suffix differs from the recorded one",
			"error_code", "kubernetes_ca_suffix_mismatch")
	}
	return matched
}

// Names returns the DNS name of each active cluster of a Network under
// suffix; a cluster whose Network has no codes yet is left out.
func Names(read kubeca.Network, suffix dnsname.Suffix) map[publicid.ID]string {
	names := map[publicid.ID]string{}
	workspaceCode, workspaceErr := identity.ParseDisplayCode(read.WorkspaceCode)
	networkCode, networkErr := identity.ParseDisplayCode(read.NetworkCode)
	if workspaceErr != nil || networkErr != nil {
		return names
	}
	zone, err := dnsname.NewZone(workspaceCode, networkCode, suffix)
	if err != nil {
		return names
	}
	for _, cluster := range read.Clusters {
		if name, ok := zone.KubernetesClusterName(cluster.Name); ok && cluster.Active {
			names[cluster.ID] = name
		}
	}
	return names
}

// keep keeps a Network's CAs in one change; when that fails, each due
// cluster alone, so one cluster does not hold back the others (§17.3).
func (worker *Worker) keep(ctx context.Context, scope network.Scope) error {
	err := worker.keepClusters(ctx, scope, publicid.ID{})
	if err == nil || errors.Is(err, ErrPlanChanged) || errors.Is(err, ErrBusy) {
		return err
	}
	read, readErr := worker.store.Read(ctx, worker.options.DeploymentID, scope)
	if readErr != nil {
		return errors.Join(err, readErr)
	}
	attempted, failed, deleted := 0, 0, false
	for _, cluster := range read.Clusters {
		if cluster.NextActionAt.After(read.Now) || ctx.Err() != nil {
			continue
		}
		attempted++
		clusterErr := worker.keepClusters(ctx, scope, cluster.ID)
		if clusterErr == nil || errors.Is(clusterErr, ErrPlanChanged) || errors.Is(clusterErr, ErrBusy) {
			continue
		}
		failed++
		worker.logger.WarnContext(ctx, "kubernetes cluster CA change deferred", "error_code", errorCode(clusterErr))
		if !cluster.Active {
			// A deleted cluster with CAs is always due again at once: the
			// Network backs off instead (review a2 M-1).
			deleted = true
			continue
		}
		if failErr := worker.failCluster(ctx, scope, cluster.ID); failErr != nil {
			return errors.Join(err, failErr)
		}
	}
	switch {
	case attempted == 0 || deleted:
		return err
	case failed == 0:
		worker.logger.WarnContext(ctx, "kubernetes CA Network change failed; its clusters were kept one by one",
			"error_code", errorCode(err))
		return nil
	}
	return errors.Join(errClustersFailed, err)
}

// restrict keeps one cluster of a read; the zero ID keeps all.
func restrict(read kubeca.Network, only publicid.ID) kubeca.Network {
	if !only.IsValid() {
		return read
	}
	restricted := read
	restricted.Clusters = nil
	for _, cluster := range read.Clusters {
		if cluster.ID == only {
			restricted.Clusters = append(restricted.Clusters, cluster)
		}
	}
	return restricted
}

// failCluster schedules one cluster for a later look, counting a failure.
func (worker *Worker) failCluster(ctx context.Context, scope network.Scope, cluster publicid.ID) error {
	busy, err := worker.store.Change(ctx, worker.options.DeploymentID, scope,
		func(locked kubeca.Network) (kubeca.Changes, error) {
			return kubeca.Changes{Schedules: []kubeca.Schedule{
				{Cluster: cluster, At: locked.Now.Add(worker.options.Policy.RetryAfter), Failed: true},
			}}, nil
		})
	if err == nil && busy {
		return ErrBusy
	}
	return err
}

// keepClusters reads a Network (or one cluster of it), decides, prepares
// keys outside any transaction, then applies under the Network's lock if
// it still needs exactly that.
func (worker *Worker) keepClusters(ctx context.Context, scope network.Scope, only publicid.ID) error {
	installation := worker.options.DeploymentID
	read, err := worker.store.Read(ctx, installation, scope)
	if err != nil {
		return err
	}
	read = restrict(read, only)
	names := Names(read, worker.options.Suffix)
	decision := Decide(read, names, worker.options.Policy)
	var steps []kubeca.Step
	if creates(decision) {
		if read, decision, err = worker.ensureDataKey(ctx, scope, read, names, decision, only); err != nil {
			return err
		}
		sealer, forget, err := worker.sealer(ctx, scope, read)
		if err != nil {
			return err
		}
		steps, err = Prepare(read, decision, sealer, worker.options.Policy, randomJitter)
		forget()
		sealer.DataKey = kubeca.DataKey{}
		if err != nil {
			return err
		}
	} else {
		steps = Steps(decision)
	}
	if len(decision.Misnamed) > 0 && !only.IsValid() {
		worker.misnamed.Add(uint64(len(decision.Misnamed)))
		worker.logger.ErrorContext(ctx, "kubernetes cluster CAs sign for another name; no CA work is done for them",
			"error_code", "kubernetes_ca_cluster_misnamed", "clusters", len(decision.Misnamed))
	}
	busy, err := worker.store.Change(ctx, installation, scope, func(locked kubeca.Network) (kubeca.Changes, error) {
		return Recheck(decision, steps, restrict(locked, only), func(read kubeca.Network) Decision {
			return Decide(read, Names(read, worker.options.Suffix), worker.options.Policy)
		})
	})
	if err != nil {
		return err
	}
	if busy {
		return ErrBusy
	}
	for _, step := range steps {
		if step.Create != nil {
			worker.created.Add(1)
		} else {
			worker.moved.Add(1)
		}
	}
	return nil
}

func creates(decision Decision) bool {
	for _, action := range decision.Actions {
		if action.Create != nil {
			return true
		}
	}
	return false
}

// Steps returns a decision's moves as stored steps; it has no creation.
func Steps(decision Decision) []kubeca.Step {
	steps := make([]kubeca.Step, 0, len(decision.Actions))
	for _, action := range decision.Actions {
		if action.Move != nil {
			move := *action.Move
			steps = append(steps, kubeca.Step{Move: &move})
		}
	}
	return steps
}

// ensureDataKey gives the Network an active data key when it has none, and
// reads it again.
func (worker *Worker) ensureDataKey(ctx context.Context, scope network.Scope, read kubeca.Network,
	names map[publicid.ID]string, decision Decision, only publicid.ID,
) (kubeca.Network, Decision, error) {
	if activeDataKey(read) != nil {
		return read, decision, nil
	}
	if worker.custody == nil {
		return read, decision, errNoCustody
	}
	_, wrapped, err := worker.custody.NewDataKey(ctx, scope.NetworkID().String())
	if err != nil {
		return read, decision, err
	}
	id, err := publicid.New()
	if err != nil {
		return read, decision, err
	}
	if _, err := worker.store.AddDataKey(ctx, worker.options.DeploymentID, scope, id, wrapped,
		kubeca.Operator{}); err != nil {
		return read, decision, err
	}
	if read, err = worker.store.Read(ctx, worker.options.DeploymentID, scope); err != nil {
		return read, decision, err
	}
	read = restrict(read, only)
	if activeDataKey(read) == nil {
		// Another worker held the Network while this one added the key.
		return read, decision, ErrBusy
	}
	return read, Decide(read, names, worker.options.Policy), nil
}

func activeDataKey(read kubeca.Network) *kubeca.StoredDataKey {
	for index := range read.DataKeys {
		if read.DataKeys[index].Active {
			return &read.DataKeys[index]
		}
	}
	return nil
}

// sealer opens the Network's data keys through the custody for one
// preparation; forget drops them once it is done (review a2 L-C).
func (worker *Worker) sealer(ctx context.Context, scope network.Scope, read kubeca.Network) (Sealer, func(),
	error,
) {
	if worker.custody == nil {
		return Sealer{}, func() {}, errNoCustody
	}
	stored := map[publicid.ID]kubeca.StoredDataKey{}
	for _, key := range read.DataKeys {
		stored[key.ID] = key
	}
	opened := map[publicid.ID]kubeca.DataKey{}
	forget := func() {
		for id := range opened {
			opened[id] = kubeca.DataKey{}
			delete(opened, id)
		}
	}
	open := func(id publicid.ID) (kubeca.DataKey, error) {
		if key, hit := opened[id]; hit {
			return key, nil
		}
		key, ok := stored[id]
		if !ok {
			return kubeca.DataKey{}, kubeca.ErrInvalid
		}
		dataKey, err := worker.custody.OpenDataKey(ctx, scope.NetworkID().String(), key.Wrapped)
		if err != nil {
			return kubeca.DataKey{}, err
		}
		opened[id] = dataKey
		return dataKey, nil
	}
	active := activeDataKey(read)
	if active == nil {
		return Sealer{}, forget, kubeca.ErrInvalid
	}
	dataKey, err := open(active.ID)
	if err != nil {
		return Sealer{}, forget, err
	}
	return Sealer{
		Installation: worker.options.DeploymentID.String(), DataKeyID: active.ID, DataKey: dataKey,
		OpenDataKey: open,
	}, forget, nil
}

// randomJitter is uniform in [-spread, spread].
func randomJitter(spread time.Duration) time.Duration {
	if spread <= 0 {
		return 0
	}
	offset, err := rand.Int(rand.Reader, big.NewInt(int64(2*spread)+1))
	if err != nil {
		return 0
	}
	return time.Duration(offset.Int64()) - spread
}

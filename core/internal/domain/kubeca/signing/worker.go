package signing

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/kubeca/lifecycle"
	"meshtransit.net/core/internal/domain/publicid"
)

const (
	// Lease is how long a claim holds a request (§4 step 1).
	Lease = 30 * time.Second
	// idleDelay is how often an idle worker looks at the queue (§4).
	idleDelay = 250 * time.Millisecond
	// beatInterval is how often the worker says it can sign; control counts
	// on it for 90 s.
	beatInterval = 30 * time.Second
	// pruneInterval is how often requests and old ledger rows are removed.
	pruneInterval = time.Minute
	pruneLimit    = 1000
	custodyRetry  = time.Minute
	// leaseMargin is how much of a lease must be left to sign a claim.
	leaseMargin = 5 * time.Second
	// maximumBackoff caps the wait after custody trouble or another
	// installation's suffix.
	maximumBackoff = 30 * time.Second
	// releaseTimeout bounds giving claims back while the worker stops.
	releaseTimeout   = 5 * time.Second
	maximumBatchSize = 32
	// uncheckedWarnAfter is how long a worker that never saw the tripwire
	// checked waits before it warns.
	uncheckedWarnAfter = 10 * time.Minute
	// The fleet is read one page per pass, a full scan every fleetInterval
	// (a4d); a certificate with less than fleetExpiring left is expiring: a
	// replica that renews on time has about 15 hours left.
	fleetInterval = 5 * time.Minute
	fleetRetry    = time.Minute
	fleetPage     = 500
	fleetExpiring = 10 * time.Hour
)

var (
	// ErrInvalidWorker rejects unsafe dependencies or bounds.
	ErrInvalidWorker = errors.New("kubernetes certificate signer: invalid configuration")
	// ErrWorkerStarted rejects duplicate lifecycle ownership.
	ErrWorkerStarted = errors.New("kubernetes certificate signer: already started")
	// ErrWorkerNotStarted rejects shutdown before startup.
	ErrWorkerNotStarted = errors.New("kubernetes certificate signer: not started")
)

// Options binds the signer to its installation, DNS suffix and pace.
type Options struct {
	DeploymentID     deployment.ID
	Suffix           dnsname.Suffix
	Version          string
	BatchSize        int
	OperationTimeout time.Duration
	// MaximumPerSecond bounds the certificates signed each second.
	MaximumPerSecond int
	// Wake, optional, ends an idle wait at once: control queued a request
	// (a Redis hint, a3 §14 R-H3).
	Wake <-chan struct{}
	// Settled, optional, tells control a request was issued or refused, so
	// a waiting session answers without polling. Best effort.
	Settled func(ctx context.Context, request publicid.ID)
}

func (options Options) valid() bool {
	return options.DeploymentID.IsValid() && options.Suffix.IsValid() && options.Version != "" &&
		options.BatchSize >= 1 && options.BatchSize <= maximumBatchSize && options.OperationTimeout >= time.Second &&
		options.OperationTimeout <= time.Minute && options.MaximumPerSecond >= 1 && options.MaximumPerSecond <= 1000
}

// Measurements are identifier-free counts for metrics.
type Measurements struct {
	Running, CustodyReady, Suspected, SuffixMismatch bool
	// Unchecked: the restore tripwire was not checked lately, so nothing is
	// signed (§14 R-M9).
	Unchecked                                  bool
	Pending                                    int64
	Issued, Requeued, Released, Lost, Failures uint64
	Refused                                    map[Reason]uint64
	// Fleet is the last full scan of the gateway Devices (a4d).
	Fleet FleetCounts
}

// FleetCounts count active gateway Devices of active clusters by their
// latest certificate: Valid, Expiring within 10 hours, or Missing (none, or
// expired). Struggling are running replicas that do not get one: the
// expiring or missing that asked within the last 10 minutes, and any whose
// latest request went unserved, whatever its latest certificate (a pod that
// restarted holds none of the certificates the ledger lists, review a4d
// M2). A replica scaled to zero asks nothing, so it is missing but never
// struggling. MeasuredAt is when the scan ended; zero: none yet. Every
// worker replica counts the whole fleet: aggregate with max().
type FleetCounts struct {
	Valid, Expiring, Missing, Struggling int64
	MeasuredAt                           time.Time
}

// Worker signs the installation's queued certificate requests. It owns one
// goroutine.
type Worker struct {
	options  Options
	store    Store
	source   lifecycle.CustodySource
	logger   *slog.Logger
	instance publicid.ID

	// Owned by the worker goroutine.
	signer       *signer
	custody      kubeca.Custody
	custodyKind  string
	custodyTried time.Time
	lastBeat     time.Time
	lastReady    bool
	lastPrune    time.Time
	// checkedOnce: a claim found the restore tripwire checked since the
	// worker started. uncheckedSince and uncheckedWarned track the current
	// stretch without a check.
	checkedOnce     bool
	uncheckedSince  time.Time
	uncheckedWarned bool
	backoffUntil    time.Time
	custodyDelay    time.Duration
	// The fleet scan in progress: its next page after fleetAfter, its
	// counts so far, and when the next scan starts.
	fleetNext    time.Time
	fleetAfter   [2]int64
	fleetPartial FleetCounts

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan error
	refused map[Reason]uint64
	fleet   FleetCounts

	running, custodyReady, suspected, suffixMismatch, unchecked atomic.Bool
	pending                                                     atomic.Int64
	issued, requeued, released, lost, failures                  atomic.Uint64
}

// New builds a stopped worker without I/O.
func New(options Options, store Store, source lifecycle.CustodySource, verifyToken TokenVerifier,
	verifyRenewal RenewalVerifier, logger *slog.Logger,
) (*Worker, error) {
	if !options.valid() || store == nil || source == nil || verifyToken == nil || verifyRenewal == nil ||
		logger == nil {
		return nil, ErrInvalidWorker
	}
	instance, err := publicid.New()
	if err != nil {
		return nil, err
	}
	return &Worker{
		options: options, store: store, source: source, logger: logger, instance: instance,
		signer:  newSigner(options.DeploymentID, options.Suffix, verifyToken, verifyRenewal),
		refused: map[Reason]uint64{},
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

// Shutdown cancels the worker; claims it holds are given back. Done is the
// join.
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
	worker.mu.Lock()
	refused := make(map[Reason]uint64, len(worker.refused))
	for reason, count := range worker.refused {
		refused[reason] = count
	}
	fleet := worker.fleet
	worker.mu.Unlock()
	return Measurements{
		Running: worker.running.Load(), CustodyReady: worker.custodyReady.Load(), Suspected: worker.suspected.Load(),
		Unchecked:      worker.unchecked.Load(),
		SuffixMismatch: worker.suffixMismatch.Load(), Pending: worker.pending.Load(), Issued: worker.issued.Load(),
		Requeued: worker.requeued.Load(), Released: worker.released.Load(), Lost: worker.lost.Load(),
		Failures: worker.failures.Load(), Refused: refused, Fleet: fleet,
	}
}

func (worker *Worker) run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	// Opened intermediates hold private keys: none outlive the worker.
	defer worker.signer.clear()
	idle := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-worker.options.Wake:
			// A request was queued: an idle worker looks now. One pacing a
			// full batch keeps its rate.
			if idle && timer.Stop() {
				idle = false
				timer.Reset(0)
			}
		case <-timer.C:
			delay := idleDelay
			idle = true
			if progressed := worker.Pass(ctx); progressed == worker.options.BatchSize {
				// A full batch settled: go on at the signing rate.
				delay = time.Duration(progressed) * time.Second / time.Duration(worker.options.MaximumPerSecond)
				idle = false
			}
			if ctx.Err() != nil {
				return
			}
			timer.Reset(delay)
		}
	}
}

// Pass is one round: custody and pruning when due, one batch of claims
// signed, then the heartbeat. It returns how many claims it settled (issued,
// refused or requeued); claims given back do not count, so a worker that
// cannot sign waits instead of claiming the same requests again at once
// (review a3a H1). Exported for tests.
func (worker *Worker) Pass(ctx context.Context) int {
	worker.loadCustody(ctx)
	worker.prune(ctx)
	worker.measureFleet(ctx)
	worker.signer.forget(time.Now())
	defer worker.beat(ctx)
	if worker.custody == nil || time.Now().Before(worker.backoffUntil) {
		return 0
	}
	claimCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	claimedAt := time.Now()
	batch, err := worker.store.Claim(claimCtx, worker.options.DeploymentID, worker.options.BatchSize, Lease)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			worker.failures.Add(1)
			worker.logger.WarnContext(ctx, "kubernetes certificates deferred", "error_code",
				"kubernetes_certificate_claim_failed")
		}
		return 0
	}
	worker.suspected.Store(batch.Suspected)
	wasUnchecked := worker.unchecked.Swap(batch.Unchecked)
	worker.pending.Store(batch.Pending)
	if batch.RefusedAttempts > 0 {
		worker.mu.Lock()
		worker.refused[ReasonAttempts] += uint64(batch.RefusedAttempts)
		worker.mu.Unlock()
	}
	if batch.Suspected {
		// Keys opened before the restore was suspected are dropped.
		worker.signer.clear()
		return 0
	}
	if batch.Unchecked {
		// The lifecycle worker has not compared the restore marks lately
		// (stopped, or Redis down): nothing is signed until it does. Told
		// once, not every pass: a WARN at once if the tripwire was found
		// checked since this worker started, else (a start) an INFO, and a
		// WARN if it stays unchecked for the 10 minutes signing tolerates.
		if !wasUnchecked {
			worker.uncheckedSince, worker.uncheckedWarned = time.Now(), false
			if !worker.checkedOnce {
				worker.logger.InfoContext(ctx, "kubernetes certificates wait for the restore tripwire's first check")
			}
		}
		if !worker.uncheckedWarned &&
			(worker.checkedOnce || time.Since(worker.uncheckedSince) >= uncheckedWarnAfter) {
			worker.uncheckedWarned = true
			worker.logger.WarnContext(ctx, "kubernetes certificates deferred: restore tripwire not checked",
				"error_code", "kubernetes_ca_tripwire_unchecked")
		}
		return 0
	}
	if wasUnchecked {
		worker.logger.InfoContext(ctx, "kubernetes certificates: restore tripwire checked, signing resumes")
	}
	worker.checkedOnce = true
	if batch.Suffix != worker.options.Suffix.String() {
		// The lifecycle worker reports the mismatch; nothing is signed
		// under another installation's names (§17.1 C2).
		worker.suffixMismatch.Store(true)
		worker.releaseAll(ctx, batch.Claims)
		worker.backOff(maximumBackoff)
		return 0
	}
	worker.suffixMismatch.Store(false)
	settled := 0
	for index, claim := range batch.Claims {
		// A claim near the end of its lease is given back rather than
		// signed for another worker to sign again (review a3a M5).
		elapsed := time.Since(claimedAt)
		if ctx.Err() != nil || elapsed > Lease-leaseMargin {
			worker.releaseAll(ctx, batch.Claims[index:])
			break
		}
		done, custodyDown := worker.handle(ctx, claim, batch.Now.Add(elapsed))
		if custodyDown {
			// The custody cannot open keys now: every claim goes back and
			// the worker waits, longer each time (review a3a H1).
			worker.releaseAll(ctx, batch.Claims[index+1:])
			worker.backOff(0)
			return settled
		}
		if done {
			settled++
		}
	}
	worker.custodyDelay = 0
	return settled
}

// backOff makes the worker wait before its next claim: delay, or else
// twice the last wait, from a second up to maximumBackoff.
func (worker *Worker) backOff(delay time.Duration) {
	if delay == 0 {
		delay = max(time.Second, min(2*worker.custodyDelay, maximumBackoff))
		worker.custodyDelay = delay
	}
	worker.backoffUntil = time.Now().Add(delay)
}

// handle signs one claim and settles it. done is false when the claim was
// given back; custodyDown when the custody itself failed. A panic while
// signing one claim refuses that claim only (§14 R-L4).
func (worker *Worker) handle(ctx context.Context, claim Claim, now time.Time) (done, custodyDown bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			worker.failures.Add(1)
			worker.logger.ErrorContext(ctx, "kubernetes certificate signing failed", "error_code",
				"kubernetes_certificate_sign_panic")
			done, custodyDown = worker.refuse(ctx, claim, ReasonInternal), false
		}
	}()
	if claim.Proof == ProofToken && claim.Verified == nil {
		verified, recorded, settled := worker.recordToken(ctx, claim, now)
		if !recorded {
			return settled, false
		}
		claim.Verified, claim.Token = &verified, ""
	}
	signCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	decided, err := worker.signer.sign(signCtx, worker.custody, claim, now)
	cancel()
	if err != nil {
		worker.failures.Add(1)
		if custodyFailure(err) || ctx.Err() != nil {
			worker.logger.ErrorContext(ctx, "kubernetes certificate not signed", "error_code", errorCode(err))
			worker.release(ctx, claim)
			return false, ctx.Err() == nil
		}
		// The cluster's CA does not open: its requests are refused, and it
		// is not tried again for a minute.
		if !errors.Is(err, errCAUnusable) {
			worker.logger.ErrorContext(ctx, "kubernetes cluster CA unusable", "error_code", errorCode(err))
		}
		decided = decision{refuse: ReasonNoCA}
	}
	// What the worker decided is settled even while it stops, within a
	// bound of its own; a claim left behind waits out its lease.
	settleCtx, cancelSettle := context.WithTimeout(context.WithoutCancel(ctx), worker.options.OperationTimeout)
	defer cancelSettle()
	if decided.refuse != "" {
		return worker.refuse(ctx, claim, decided.refuse), false
	}
	outcome, reason, err := worker.store.Issue(settleCtx, worker.options.DeploymentID, decided.issue)
	if err == nil && (outcome == OutcomeIssued || outcome == OutcomeRefused) {
		worker.settled(settleCtx, claim.ID)
	}
	if outcome == OutcomeRequeued {
		worker.signer.drop(claim.Intermediate.ID)
	}
	if outcome == OutcomeSuspected {
		worker.suspected.Store(true)
		worker.signer.clear()
	}
	worker.count(outcome, reason, err)
	return err == nil && (outcome == OutcomeIssued || outcome == OutcomeRefused || outcome == OutcomeRequeued), false
}

// recordToken checks a token request's pod token at its first claim and
// replaces it in the database with the claims checked (§14 R-M1), or
// refuses the request. When nothing is to be signed, recorded is false and
// settled says whether the claim was settled (refused or lost); a claim
// whose record failed is given back, not counted as progress (review a3b
// Go M6).
func (worker *Worker) recordToken(ctx context.Context, claim Claim, now time.Time) (verified VerifiedToken,
	recorded, settled bool,
) {
	verified, reason := worker.signer.checkToken(claim, now)
	if reason != "" {
		return VerifiedToken{}, false, worker.refuse(ctx, claim, reason)
	}
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), worker.options.OperationTimeout)
	defer cancel()
	outcome, err := worker.store.RecordToken(recordCtx, worker.options.DeploymentID, claim.ID, claim.ClaimToken,
		verified)
	switch {
	case err != nil:
		worker.count(outcome, "", err)
		worker.release(ctx, claim)
		return VerifiedToken{}, false, false
	case outcome != OutcomeRecorded:
		worker.count(outcome, "", nil)
		return VerifiedToken{}, false, true
	}
	return verified, true, true
}

// refuse settles a held claim as refused for reason, within a bound of its
// own so a stopping worker still does. It reports whether it was.
func (worker *Worker) refuse(ctx context.Context, claim Claim, reason Reason) bool {
	settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), worker.options.OperationTimeout)
	defer cancel()
	outcome, err := worker.store.Refuse(settleCtx, worker.options.DeploymentID, claim.ID, claim.ClaimToken, reason)
	worker.count(outcome, reason, err)
	if err == nil && outcome == OutcomeRefused {
		worker.settled(settleCtx, claim.ID)
		return true
	}
	return false
}

// settled tells control, if it listens, that request was settled.
func (worker *Worker) settled(ctx context.Context, request publicid.ID) {
	if worker.options.Settled != nil {
		worker.options.Settled(ctx, request)
	}
}

// custodyFailure reports an error of the custody as a whole, as opposed to
// one CA that does not open.
func custodyFailure(err error) bool {
	return errors.Is(err, kubeca.ErrUnavailable) || errors.Is(err, kubeca.ErrMisconfigured) ||
		errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
}

func (worker *Worker) count(outcome Outcome, reason Reason, err error) {
	if err != nil {
		worker.failures.Add(1)
		worker.logger.Warn("kubernetes certificate not settled", "error_code", "kubernetes_certificate_store_failed")
		return
	}
	switch outcome {
	case OutcomeIssued:
		worker.issued.Add(1)
	case OutcomeRefused:
		if !reason.Known() {
			reason = ReasonOther
		}
		worker.mu.Lock()
		worker.refused[reason]++
		worker.mu.Unlock()
	case OutcomeRequeued:
		worker.requeued.Add(1)
	case OutcomeReleased, OutcomeSuspected:
		worker.released.Add(1)
	case OutcomeLost:
		worker.lost.Add(1)
	}
}

// release gives a claim back, with a bounded context of its own so a
// stopping worker still does.
func (worker *Worker) release(ctx context.Context, claim Claim) {
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()
	outcome, err := worker.store.Release(releaseCtx, worker.options.DeploymentID, claim.ID, claim.ClaimToken)
	worker.count(outcome, "", err)
}

func (worker *Worker) releaseAll(ctx context.Context, claims []Claim) {
	for _, claim := range claims {
		worker.release(ctx, claim)
	}
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, kubeca.ErrMisconfigured):
		return "kubernetes_ca_custody_misconfigured"
	case errors.Is(err, kubeca.ErrUnavailable):
		return "kubernetes_ca_custody_unavailable"
	case errors.Is(err, kubeca.ErrInvalid):
		return "kubernetes_ca_invalid"
	}
	return "kubernetes_certificate_sign_failed"
}

// loadCustody builds the custody again every minute, as the lifecycle
// worker does; a failed read keeps the custody it had.
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
		worker.logger.ErrorContext(ctx, "kubernetes certificate custody unavailable", "error_code",
			"kubernetes_ca_custody_missing", "kept", worker.custody != nil)
		return
	}
	worker.custody, worker.custodyKind = custody, kind
	worker.custodyReady.Store(true)
}

// beat says, every 30 s and whenever it changes, whether this process can
// sign for the next 90 s: with a custody that answers, no restore suspected
// and the recorded suffix. It runs after the claim, which tells the last two.
func (worker *Worker) beat(ctx context.Context) {
	ready := worker.custody != nil && !worker.suspected.Load() && !worker.unchecked.Load() &&
		!worker.suffixMismatch.Load() && !time.Now().Before(worker.backoffUntil)
	// A change of readiness is told at once (review a3a M4).
	if !worker.lastBeat.IsZero() && time.Since(worker.lastBeat) < beatInterval && ready == worker.lastReady {
		return
	}
	worker.lastBeat, worker.lastReady = time.Now(), ready
	custody := worker.custodyKind
	if custody == "" {
		custody = "none"
	}
	beatCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	if _, err := worker.store.Beat(beatCtx, worker.options.DeploymentID, worker.instance, ready,
		worker.options.Version, custody, []string{Capability}); err != nil && ctx.Err() == nil {
		worker.logger.WarnContext(ctx, "kubernetes certificate heartbeat failed", "error_code",
			"kubernetes_ca_beat_failed")
	}
}

// prune removes ended requests and old ledger rows every minute.
func (worker *Worker) prune(ctx context.Context) {
	if !worker.lastPrune.IsZero() && time.Since(worker.lastPrune) < pruneInterval {
		return
	}
	worker.lastPrune = time.Now()
	pruneCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	if _, _, err := worker.store.Prune(pruneCtx, worker.options.DeploymentID, pruneLimit); err != nil &&
		ctx.Err() == nil {
		worker.logger.WarnContext(ctx, "kubernetes certificate pruning failed", "error_code",
			"kubernetes_certificate_prune_failed")
	}
}

// measureFleet reads one page of the gateway fleet when a scan is due, so a
// pass never waits on more than one bounded read (a4d). The counts are
// published when the last page is read; a failed read starts over later.
func (worker *Worker) measureFleet(ctx context.Context) {
	now := time.Now()
	if now.Before(worker.fleetNext) {
		return
	}
	readCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	rows, err := worker.store.Fleet(readCtx, worker.options.DeploymentID, worker.fleetAfter[0],
		int(worker.fleetAfter[1]), fleetPage)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			worker.logger.WarnContext(ctx, "kubernetes gateway certificate fleet read failed", "error_code",
				"kubernetes_certificate_fleet_failed")
		}
		worker.fleetAfter, worker.fleetPartial, worker.fleetNext = [2]int64{}, FleetCounts{}, now.Add(fleetRetry)
		return
	}
	for _, row := range rows {
		missing := !row.NotAfter.After(now)
		expiring := !missing && row.NotAfter.Before(now.Add(fleetExpiring))
		switch {
		case missing:
			worker.fleetPartial.Missing++
		case expiring:
			worker.fleetPartial.Expiring++
		default:
			worker.fleetPartial.Valid++
		}
		if row.Unserved || row.Asking && (missing || expiring) {
			worker.fleetPartial.Struggling++
		}
		worker.fleetAfter = [2]int64{row.Cluster, int64(row.Ordinal)}
	}
	if len(rows) == fleetPage {
		return
	}
	worker.fleetPartial.MeasuredAt = now
	worker.mu.Lock()
	worker.fleet = worker.fleetPartial
	worker.mu.Unlock()
	worker.fleetAfter, worker.fleetPartial, worker.fleetNext = [2]int64{}, FleetCounts{}, now.Add(fleetInterval)
}

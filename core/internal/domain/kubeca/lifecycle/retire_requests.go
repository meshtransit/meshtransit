package lifecycle

import (
	"context"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// RetireRequestBatch bounds the requests one pass carries out.
const RetireRequestBatch = 16

var (
	// errRetireChanged reports a CA that moved past the version asked for.
	errRetireChanged = errors.New("kubernetes CA lifecycle: the CA changed since the request")
	// errRetireMissing reports a CA the Network's locked read does not hold
	// although it is not retired: the request waits for a later pass.
	errRetireMissing = errors.New("kubernetes CA lifecycle: the CA is not in the Network's read")
	// errRetireExpired reports a request past its hour by the locked clock.
	errRetireExpired = errors.New("kubernetes CA lifecycle: the request expired")
)

// retireChanges retires target, a root with every intermediate it issued
// that is not retired, and schedules its cluster now so the worker gives it
// new CAs (§17.2).
func retireChanges(locked kubeca.Network, cluster kubeca.Cluster, target kubeca.StoredCA, reason kubeca.Reason,
	operator kubeca.Operator) kubeca.Changes {
	changes := kubeca.Changes{Operator: operator, Schedules: []kubeca.Schedule{{Cluster: cluster.ID, At: locked.Now}}}
	if target.Kind == kubeca.KindRoot {
		for _, below := range cluster.CAs {
			if below.Kind == kubeca.KindIntermediate && below.IssuerID == target.ID {
				changes.Steps = append(changes.Steps, retireStep(below, reason))
			}
		}
	}
	changes.Steps = append(changes.Steps, retireStep(target, reason))
	return changes
}

// findCA returns the CA id of the locked read and its cluster.
func findCA(locked kubeca.Network, id publicid.ID) (kubeca.Cluster, kubeca.StoredCA, bool) {
	for _, cluster := range locked.Clusters {
		for _, ca := range cluster.CAs {
			if ca.ID == id {
				return cluster, ca, true
			}
		}
	}
	return kubeca.Cluster{}, kubeca.StoredCA{}, false
}

// retireRequests carries out people's waiting requests (K1d §4.1, Q159):
// before the restore guard stops the rest of the pass, since retiring for
// a compromise is always the safe way. It returns the requests it ended.
func (worker *Worker) retireRequests(ctx context.Context, guard guardState) int {
	if worker.options.Requests == nil {
		return 0
	}
	listCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	requests, err := worker.options.Requests.List(listCtx, worker.options.DeploymentID, RetireRequestBatch)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			worker.logger.WarnContext(ctx, "kubernetes CA retire requests deferred", "error_code",
				"kubernetes_ca_retire_read_failed")
		}
		return 0
	}
	if len(requests.Waiting) == 0 {
		return 0
	}
	ended := 0
	for _, request := range requests.Waiting {
		if ctx.Err() != nil {
			return ended
		}
		refusal, done := worker.retireRequest(ctx, requests, request, guard)
		switch {
		case done:
			ended++
			worker.retired.Add(1)
			worker.logger.WarnContext(ctx, "kubernetes CA retired at a request",
				"event", "kubernetes_ca_retired", "request_id", request.ID.String(), "ca_id", request.CA.String(),
				"reason", string(request.Reason), "network_id", request.Scope.NetworkID().String())
		case refusal != "":
			refuseCtx, stop := context.WithTimeout(ctx, worker.options.OperationTimeout)
			refused, err := worker.options.Requests.Refuse(refuseCtx, worker.options.DeploymentID, request.Scope,
				request.ID, refusal)
			stop()
			if err != nil {
				if ctx.Err() == nil {
					worker.logger.WarnContext(ctx, "kubernetes CA retire request not refused", "error_code",
						"kubernetes_ca_retire_refuse_failed", "request_id", request.ID.String())
				}
				continue
			}
			if refused {
				ended++
				worker.retireRefused.Add(1)
				worker.logger.WarnContext(ctx, "kubernetes CA retire request refused",
					"event", "kubernetes_ca_retire_refused", "request_id", request.ID.String(),
					"ca_id", request.CA.String(), "refusal", refusal)
			}
		}
	}
	return ended
}

// retireRequest decides one request: done, a refusal, or neither (it waits
// for a later pass: the Network is busy, a read failed).
func (worker *Worker) retireRequest(ctx context.Context, queue RetireQueue, request kubeca.RetireRequest,
	guard guardState) (string, bool) {
	compromise := request.Reason == kubeca.ReasonCompromise
	switch {
	case !queue.Now.Before(request.ExpiresAt):
		return kubeca.RetireRefusalExpired, false
	case request.CAState == kubeca.StateRetired:
		return kubeca.RetireRefusalGone, false
	// A restore suspected stops all CA work but a compromise, which only
	// marks and drops keys: the safe way (Q162).
	case guard == guardOn && !compromise:
		return kubeca.RetireRefusalGuard, false
	// A guard that cannot be read, or marks that cannot be compared, is no
	// reason to refuse: the request waits for a pass that knows.
	case (guard == guardUnknown || guard == guardMarksUnknown) && !compromise:
		return "", false
	}
	operationCtx, cancel := context.WithTimeout(ctx, worker.options.OperationTimeout)
	defer cancel()
	operator := kubeca.RetireRequestOperator(request.ID)
	busy, err := worker.store.Change(operationCtx, worker.options.DeploymentID, request.Scope,
		func(locked kubeca.Network) (kubeca.Changes, error) {
			cluster, target, found := findCA(locked, request.CA)
			switch {
			// Expiry by the clock under the lock: a late item of a batch
			// does not run past its hour.
			case !locked.Now.Before(request.ExpiresAt):
				return kubeca.Changes{}, errRetireExpired
			case !found || cluster.ID != request.Cluster:
				return kubeca.Changes{}, errRetireMissing
			case target.Version != request.CAVersion:
				return kubeca.Changes{}, errRetireChanged
			}
			changes := retireChanges(locked, cluster, target, request.Reason, operator)
			changes.Completes = request.ID
			return changes, nil
		})
	switch {
	case err == nil && !busy:
		return "", true
	case errors.Is(err, errRetireChanged):
		return kubeca.RetireRefusalChanged, false
	case errors.Is(err, errRetireExpired):
		return kubeca.RetireRefusalExpired, false
	case errors.Is(err, errRetireMissing), busy:
		return "", false
	default:
		if ctx.Err() == nil {
			worker.logger.WarnContext(ctx, "kubernetes CA retire request deferred", "error_code",
				errorCode(err), "request_id", request.ID.String())
		}
		return "", false
	}
}

// guardState is the restore guard as one pass read it.
type guardState int

const (
	guardOff guardState = iota
	guardOn
	guardUnknown
	guardMarksUnknown
)

// stopsLifecycle reports a guard that stops CA lifecycle work: a restore
// suspected, or a guard that cannot be read. Marks that cannot be compared
// stop none (Redis is never the authority).
func (state guardState) stopsLifecycle() bool { return state == guardOn || state == guardUnknown }

// RetireQueue is one read of the waiting requests, with the database's
// clock that decides their expiry.
type RetireQueue struct {
	Now     time.Time
	Waiting []kubeca.RetireRequest
}

// RetireRequests is the worker's view of people's requests to retire a CA
// (K1d §4.1, schema 252; the postgres adapter).
type RetireRequests interface {
	List(ctx context.Context, installation deployment.ID, limit int) (RetireQueue, error)
	Refuse(ctx context.Context, installation deployment.ID, scope network.Scope, request publicid.ID,
		refusal string) (bool, error)
}

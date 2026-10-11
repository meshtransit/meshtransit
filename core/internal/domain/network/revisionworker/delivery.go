package revisionworker

import (
	"context"
	"errors"
	"fmt"

	"meshtransit.net/core/internal/domain/network"
)

// dispatchOnce claims one bounded batch and delivers it, reporting how many
// events it claimed (a full batch means more may be waiting). Streams read
// up to the newest revision on any wakeup, so revisions of one Network in
// the batch share a single wakeup carrying the newest; every claim is still
// loaded, published for and marked individually.
func (dispatcher *Dispatcher) dispatchOnce(ctx context.Context) (int, error) {
	var dispatchErrors []error
	if err := dispatcher.observeBacklog(ctx); err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		dispatchErrors = append(dispatchErrors, fmt.Errorf("observe backlog: %w", err))
	}

	claims, err := dispatcher.claim(ctx)
	dispatcher.telemetry.recordClaim(len(claims), err)
	if err != nil {
		return 0, errors.Join(
			append(dispatchErrors, fmt.Errorf("claim revisions: %w", err))...,
		)
	}
	if len(claims) > dispatcher.options.BatchSize {
		dispatcher.telemetry.recordDelivery(deliveryFailed)
		return 0, errors.Join(append(dispatchErrors, ErrInvalidClaimBatch)...)
	}

	groups, order, loadErrors := dispatcher.loadClaims(ctx, claims)
	dispatchErrors = append(dispatchErrors, loadErrors...)
	for _, networkID := range order {
		if ctx.Err() != nil {
			return len(claims), errors.Join(append(dispatchErrors, ctx.Err())...)
		}
		dispatchErrors = append(dispatchErrors, dispatcher.deliverGroup(ctx, groups[networkID])...)
	}
	return len(claims), errors.Join(dispatchErrors...)
}

// claimGroup is the loaded claims of one Network and its newest revision.
type claimGroup struct {
	newest network.RevisionAdvanced
	claims []network.RevisionClaim
}

// loadClaims loads every valid claim, deferring those that fail to load,
// and groups the rest by Network in first-seen order.
func (dispatcher *Dispatcher) loadClaims(
	ctx context.Context,
	claims []network.RevisionClaim,
) (map[network.ID]*claimGroup, []network.ID, []error) {
	groups := make(map[network.ID]*claimGroup, len(claims))
	order := make([]network.ID, 0, len(claims))
	var loadErrors []error
	for _, claim := range claims {
		if ctx.Err() != nil {
			return groups, order, append(loadErrors, ctx.Err())
		}
		if !claim.IsValid() {
			dispatcher.telemetry.recordDelivery(deliveryFailed)
			loadErrors = append(loadErrors, ErrInvalidClaimBatch)
			continue
		}
		revision, err := dispatcher.load(ctx, claim)
		if err != nil {
			if ctx.Err() != nil {
				dispatcher.telemetry.recordDelivery(deliveryFailed)
				return groups, order, append(loadErrors, ctx.Err())
			}
			if deferErr := dispatcher.deferClaim(ctx, claim, errorClassLoadRevision, err); deferErr != nil {
				dispatcher.telemetry.recordDelivery(deliveryFailed)
				loadErrors = append(loadErrors, deferErr)
				continue
			}
			dispatcher.telemetry.recordDelivery(deliveryDeferred)
			continue
		}
		group, exists := groups[revision.NetworkID()]
		if !exists {
			group = &claimGroup{newest: revision}
			groups[revision.NetworkID()] = group
			order = append(order, revision.NetworkID())
		}
		if revision.Number() > group.newest.Number() {
			group.newest = revision
		}
		group.claims = append(group.claims, claim)
	}
	return groups, order, loadErrors
}

// deliverGroup publishes one wakeup for a Network's newest revision, then
// marks each of its claims delivered; a failed publish defers them all.
func (dispatcher *Dispatcher) deliverGroup(ctx context.Context, group *claimGroup) []error {
	var deliveryErrors []error
	if err := dispatcher.publish(ctx, group.newest); err != nil {
		for _, claim := range group.claims {
			if ctx.Err() != nil {
				dispatcher.telemetry.recordDelivery(deliveryFailed)
				return append(deliveryErrors, ctx.Err())
			}
			if deferErr := dispatcher.deferClaim(ctx, claim, errorClassPublishWakeup, err); deferErr != nil {
				dispatcher.telemetry.recordDelivery(deliveryFailed)
				deliveryErrors = append(deliveryErrors, deferErr)
				continue
			}
			dispatcher.telemetry.recordDelivery(deliveryDeferred)
		}
		return deliveryErrors
	}
	for _, claim := range group.claims {
		if err := dispatcher.markDelivered(ctx, claim); err != nil {
			dispatcher.telemetry.recordDelivery(deliveryFailed)
			deliveryErrors = append(deliveryErrors, fmt.Errorf("mark revision delivered: %w", err))
			continue
		}
		dispatcher.telemetry.recordDelivery(deliveryDelivered)
	}
	return deliveryErrors
}

func (dispatcher *Dispatcher) observeBacklog(ctx context.Context) error {
	operationCtx, cancel := context.WithTimeout(ctx, dispatcher.options.OperationTimeout)
	defer cancel()
	backlog, err := dispatcher.outbox.ReadNetworkRevisionBacklog(operationCtx)
	if err != nil {
		dispatcher.telemetry.recordBacklogError()
		return err
	}
	if !backlog.isValid() {
		dispatcher.telemetry.recordBacklogError()
		return ErrInvalidBacklog
	}
	dispatcher.telemetry.recordBacklog(backlog)
	return nil
}

func (dispatcher *Dispatcher) deferClaim(
	ctx context.Context,
	claim network.RevisionClaim,
	errorClass string,
	cause error,
) error {
	retryCtx, cancel := context.WithTimeout(ctx, dispatcher.options.OperationTimeout)
	defer cancel()
	if err := dispatcher.outbox.RetryNetworkRevision(
		retryCtx,
		claim,
		errorClass,
		dispatcher.options.RetryDelay,
	); err != nil {
		return errors.Join(
			fmt.Errorf("defer revision delivery: %w", err),
			fmt.Errorf("delivery failure: %w", cause),
		)
	}
	dispatcher.logger.WarnContext(
		ctx,
		"network revision delivery deferred",
		"error_code", errorClass,
		"attempt", claim.Attempt(),
		"error", cause,
	)
	return nil
}

func (dispatcher *Dispatcher) claim(ctx context.Context) ([]network.RevisionClaim, error) {
	operationCtx, cancel := context.WithTimeout(ctx, dispatcher.options.OperationTimeout)
	defer cancel()
	return dispatcher.outbox.ClaimNetworkRevisions(
		operationCtx,
		dispatcher.options.WorkerID,
		dispatcher.options.BatchSize,
		dispatcher.options.Lease,
	)
}

func (dispatcher *Dispatcher) load(
	ctx context.Context,
	claim network.RevisionClaim,
) (network.RevisionAdvanced, error) {
	operationCtx, cancel := context.WithTimeout(ctx, dispatcher.options.OperationTimeout)
	defer cancel()
	return dispatcher.outbox.LoadNetworkRevision(operationCtx, claim)
}

func (dispatcher *Dispatcher) publish(
	ctx context.Context,
	revision network.RevisionAdvanced,
) error {
	operationCtx, cancel := context.WithTimeout(ctx, dispatcher.options.OperationTimeout)
	defer cancel()
	return dispatcher.publisher.PublishNetworkRevisionAdvanced(operationCtx, revision)
}

func (dispatcher *Dispatcher) markDelivered(
	ctx context.Context,
	claim network.RevisionClaim,
) error {
	operationCtx, cancel := context.WithTimeout(ctx, dispatcher.options.OperationTimeout)
	defer cancel()
	return dispatcher.outbox.MarkRevisionDelivered(operationCtx, claim)
}

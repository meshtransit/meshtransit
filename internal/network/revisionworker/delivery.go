package revisionworker

import (
	"context"
	"errors"
	"fmt"

	"github.com/meshtransit/meshtransit/internal/network"
)

func (dispatcher *Dispatcher) dispatchOnce(ctx context.Context) error {
	var dispatchErrors []error
	if err := dispatcher.observeBacklog(ctx); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		dispatchErrors = append(dispatchErrors, fmt.Errorf("observe backlog: %w", err))
	}

	claims, err := dispatcher.claim(ctx)
	dispatcher.telemetry.recordClaim(len(claims), err)
	if err != nil {
		return errors.Join(
			append(dispatchErrors, fmt.Errorf("claim revisions: %w", err))...,
		)
	}
	if len(claims) > dispatcher.options.BatchSize {
		dispatcher.telemetry.recordDelivery(deliveryFailed)
		return errors.Join(append(dispatchErrors, ErrInvalidClaimBatch)...)
	}

	for _, claim := range claims {
		if ctx.Err() != nil {
			return errors.Join(append(dispatchErrors, ctx.Err())...)
		}
		if !claim.IsValid() {
			dispatcher.telemetry.recordDelivery(deliveryFailed)
			dispatchErrors = append(dispatchErrors, ErrInvalidClaimBatch)
			continue
		}
		outcome, err := dispatcher.dispatchClaim(ctx, claim)
		dispatcher.telemetry.recordDelivery(outcome)
		if err != nil {
			dispatchErrors = append(dispatchErrors, err)
		}
	}
	return errors.Join(dispatchErrors...)
}

func (dispatcher *Dispatcher) dispatchClaim(
	ctx context.Context,
	claim network.RevisionClaim,
) (deliveryOutcome, error) {
	revision, err := dispatcher.load(ctx, claim)
	if err != nil {
		if ctx.Err() != nil {
			return deliveryFailed, ctx.Err()
		}
		if deferErr := dispatcher.deferClaim(ctx, claim, errorClassLoadRevision, err); deferErr != nil {
			return deliveryFailed, deferErr
		}
		return deliveryDeferred, nil
	}
	if err := dispatcher.publish(ctx, revision); err != nil {
		if ctx.Err() != nil {
			return deliveryFailed, ctx.Err()
		}
		if deferErr := dispatcher.deferClaim(ctx, claim, errorClassPublishWakeup, err); deferErr != nil {
			return deliveryFailed, deferErr
		}
		return deliveryDeferred, nil
	}
	if err := dispatcher.markDelivered(ctx, claim); err != nil {
		return deliveryFailed, fmt.Errorf("mark revision delivered: %w", err)
	}
	return deliveryDelivered, nil
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

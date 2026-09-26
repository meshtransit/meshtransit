package oidcauth

import (
	"context"
	"errors"
	"time"
)

// CompleteBrowser composes fresh verification, confirmed consumption, one
// exchange, existing-subject read and confirmed issuance. HTTP admission must
// precede this call. Any error returns zero result; never automatically retry.
// Before issuance, a confirmed claim may be erased once with bounded joined
// cleanup. After invoking issuance ANY error delegates reconciliation to expiry,
// because even confirmed Commit can fail its release check. No failure then.
func (service *CallbackService) CompleteBrowser(
	ctx context.Context,
	command CallbackCommand,
) (result CallbackResult, resultErr error) {
	if ctx == nil || service == nil || service.active == nil {
		return result, ErrInvalidCallback
	}
	startedAt := time.Now()
	service.observer.CallbackOpened()
	defer func() {
		service.observer.CallbackClosed(callbackOutcome(result, resultErr), time.Since(startedAt))
	}()
	ctx, cancel := context.WithTimeout(ctx, service.options.RequestTimeout)
	defer cancel()
	if !command.IsValid() || ctx.Err() != nil {
		return result, errors.Join(ErrCallbackRejected, ctx.Err())
	}
	select {
	case service.active <- struct{}{}:
		defer func() { <-service.active }()
	default:
		return result, ErrCallbackLimited
	}
	params := command.params
	verified, err := service.verification.VerifyBrowser(
		ctx,
		params.Route,
		params.State,
		params.PreAuthCookie,
	)
	if err != nil {
		return result, safeCallbackError(err)
	}
	receipt, err := service.claim.ClaimBrowser(ctx, verified)
	if err != nil {
		// Zero receipt includes unknown Commit and post-commit release failure.
		return result, safeCallbackError(err)
	}
	if ctx.Err() != nil || !liveClaimAtLocalClock(receipt.claimed, service.clock.Now()) {
		return result, service.failBeforeIssue(ctx, receipt, errors.Join(ErrCallbackRejected, ctx.Err()))
	}
	if params.Kind == CallbackProviderErrorReceived {
		failure, err := service.failConfirmed(ctx, receipt)
		if err != nil {
			return result, err
		}
		now := service.clock.Now()
		if ctx.Err() != nil || !authorityTimeReached(now, failure.terminal.at) || !liveClaimAtLocalClock(receipt.claimed, now) {
			return result, errors.Join(ErrCallbackRejected, ctx.Err())
		}
		return CallbackResult{failure: failure}, nil
	}
	exchange, err := service.exchange.ExchangeBrowser(ctx, receipt, params.Code)
	if err != nil {
		return result, service.failBeforeIssue(ctx, receipt, err)
	}
	subject, err := service.subject.ResolveBrowser(ctx, exchange)
	if err != nil {
		return result, service.failBeforeIssue(ctx, receipt, err)
	}
	if ctx.Err() != nil || !liveSubjectExchange(exchange, service.clock.Now()) {
		return result, service.failBeforeIssue(ctx, receipt, errors.Join(ErrCallbackRejected, ctx.Err()))
	}
	issued, err := service.issue.IssueBrowser(ctx, exchange, subject)
	if err != nil {
		// Never infer non-commit from an error, not even a time/cancellation error.
		return result, safeCallbackError(err)
	}
	if ctx.Err() != nil || !liveIssuedRelease(exchange, issued.issued, service.clock.Now()) {
		return result, errors.Join(ErrCallbackRejected, ctx.Err())
	}
	return CallbackResult{issued: issued}, nil
}

func (service *CallbackService) failBeforeIssue(ctx context.Context, receipt ClaimResult, cause error) error {
	_, cleanupErr := service.failConfirmed(ctx, receipt)
	return errors.Join(safeCallbackError(cause), cleanupErr)
}

func (service *CallbackService) failConfirmed(ctx context.Context, receipt ClaimResult) (FailureResult, error) {
	// One synchronous owned cleanup attempt. Its service may separately join a
	// bounded rollback; neither context allows further exchange or issuance work.
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), service.options.FailureTimeout)
	defer cancel()
	failure, err := service.failure.FailBrowser(cleanup, receipt)
	if err != nil || cleanup.Err() != nil || !failure.IsValid() {
		return FailureResult{}, errors.Join(ErrCallbackCleanupFailed, safeCallbackError(errors.Join(err, cleanup.Err())))
	}
	return failure, nil
}

// Never return arbitrary port error chains. Preserve only closed classifications
// and standard cancellation/unknown-acknowledgement signals needed by the caller.
func safeCallbackError(err error) error {
	category := ErrCallbackRejected
	switch {
	case errors.Is(err, ErrExchangeLimited), errors.Is(err, ErrSubjectResolutionLimited), errors.Is(err, ErrIssueLimited):
		category = ErrCallbackLimited
	case errors.Is(err, ErrClaimCleanupFailed), errors.Is(err, ErrIssueCleanupFailed),
		errors.Is(err, ErrFailureCleanupFailed):
		category = ErrCallbackCleanupFailed
	case errors.Is(err, ErrBrowserVerificationUnavailable), errors.Is(err, ErrClaimFailed),
		errors.Is(err, ErrExchangeUnavailable), errors.Is(err, ErrSubjectResolutionUnavailable),
		errors.Is(err, ErrIssueUnavailable), errors.Is(err, ErrFailureFailed):
		category = ErrCallbackUnavailable
	}
	result := category
	for _, signal := range []error{ErrCommitOutcomeUnknown, context.Canceled, context.DeadlineExceeded} {
		if errors.Is(err, signal) {
			result = errors.Join(result, signal)
		}
	}
	return result
}

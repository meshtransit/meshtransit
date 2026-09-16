package oidcauth

import (
	"errors"
	"log/slog"
	"time"
)

// CallbackOutcome is closed operator metadata, never identity or authorization.
type CallbackOutcome uint8

const (
	// CallbackOutcomeUnknown conceals unsupported observation values.
	CallbackOutcomeUnknown CallbackOutcome = iota
	// CallbackIssued means confirmed fresh Session evidence was released, not RBAC.
	CallbackIssued
	// CallbackFailed means a provider-error callback confirmed no-grant erasure.
	CallbackFailed
	// CallbackRejected includes invalid proof, no access, expiry and cancellation.
	CallbackRejected
	// CallbackLimited reports fail-fast capacity exhaustion.
	CallbackLimited
	// CallbackUnavailable reports a dependency failure without private details.
	CallbackUnavailable
	// CallbackCommitUnknown reports lost acknowledgement, never a retry grant.
	CallbackCommitUnknown
	// CallbackCleanupFailed reports failed joined cleanup; expiry remains required.
	CallbackCleanupFailed
)

// String maps arbitrary observation values into a fixed bounded label set.
func (outcome CallbackOutcome) String() string {
	switch outcome {
	case CallbackIssued:
		return "issued"
	case CallbackFailed:
		return "failed"
	case CallbackRejected:
		return "rejected"
	case CallbackLimited:
		return "limited"
	case CallbackUnavailable:
		return "unavailable"
	case CallbackCommitUnknown:
		return "commit_unknown"
	case CallbackCleanupFailed:
		return "cleanup_failed"
	default:
		return "unknown"
	}
}

// CallbackObserver accepts no credentials, route, identity or dependency text.
// Implementations must be nonblocking and safe for concurrent callers.
type CallbackObserver interface {
	// CallbackOpened observes work lifetime including fail-fast rejections.
	CallbackOpened()
	// CallbackClosed includes synchronous cleanup in the final outcome/duration.
	CallbackClosed(CallbackOutcome, time.Duration)
}

// CallbackResult is either confirmed issuance or confirmed no-grant failure,
// never both. Only a protected BFF cookie boundary may access its issued bearer.
type CallbackResult struct {
	issued  IssueResult
	failure FailureResult
}

// IsValid checks confirmed result shape, not current durable authority or RBAC.
func (result CallbackResult) IsValid() bool {
	return result.issued.IsValid() != result.failure.IsValid()
}

// Issued returns confirmed Session evidence; zero for a no-grant terminal result.
func (result CallbackResult) Issued() IssueResult { return result.issued }

// Failure returns confirmed no-grant erasure; zero for an issued Session result.
func (result CallbackResult) Failure() FailureResult { return result.failure }

// String prevents accidental callback result credential disclosure.
func (CallbackResult) String() string { return "[REDACTED]" }

// GoString prevents detailed result credential disclosure.
func (CallbackResult) GoString() string { return "oidcauth.CallbackResult([REDACTED])" }

// LogValue prevents structured-log result credential disclosure.
func (CallbackResult) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// MarshalJSON refuses Session bearer and identity serialization.
func (CallbackResult) MarshalJSON() ([]byte, error) { return nil, ErrInvalidCallback }

func callbackOutcome(result CallbackResult, err error) CallbackOutcome {
	switch {
	case errors.Is(err, ErrCallbackCleanupFailed):
		return CallbackCleanupFailed
	case errors.Is(err, ErrCommitOutcomeUnknown):
		return CallbackCommitUnknown
	case errors.Is(err, ErrCallbackLimited):
		return CallbackLimited
	case errors.Is(err, ErrCallbackUnavailable):
		return CallbackUnavailable
	case err != nil:
		return CallbackRejected
	case result.IsValid() && result.issued.IsValid():
		return CallbackIssued
	case result.IsValid() && result.failure.IsValid():
		return CallbackFailed
	default:
		return CallbackOutcomeUnknown
	}
}

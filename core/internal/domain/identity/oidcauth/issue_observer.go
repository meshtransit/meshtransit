package oidcauth

import (
	"errors"
	"time"
)

// IssueOutcome is a closed no-data result category; zero is unknown.
type IssueOutcome uint8

const (
	// IssueUnknown is unclassified evidence, never successful issuance.
	IssueUnknown IssueOutcome = iota
	// IssueConfirmed records confirmed, live bearer release.
	IssueConfirmed
	// IssueRejected records invalid or stale authentication evidence.
	IssueRejected
	// IssueUnavailable records dependency or write-metadata failure.
	IssueUnavailable
	// IssueLimited records non-queuing saturation.
	IssueLimited
	// IssueCommitUnknown records an undisclosed uncertain write.
	IssueCommitUnknown
	// IssueCleanupFailed records joined owned-resource cleanup failure.
	IssueCleanupFailed
)

// IssueObserver must be nonblocking and concurrency-safe. It receives no route,
// bearer, identity, assurance, digest, or dependency error.
type IssueObserver interface {
	IssueOpened()
	IssueClosed(IssueOutcome, time.Duration)
}

func issueOutcome(err error) IssueOutcome {
	switch {
	case err == nil:
		return IssueConfirmed
	case errors.Is(err, ErrIssueCleanupFailed):
		return IssueCleanupFailed
	case errors.Is(err, ErrCommitOutcomeUnknown):
		return IssueCommitUnknown
	case errors.Is(err, ErrIssueLimited):
		return IssueLimited
	case errors.Is(err, ErrIssueRejected), errors.Is(err, ErrInvalidIssue):
		return IssueRejected
	default:
		return IssueUnavailable
	}
}

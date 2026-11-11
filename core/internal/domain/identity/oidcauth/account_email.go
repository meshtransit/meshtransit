package oidcauth

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"meshtransit.net/core/internal/domain/displayemail"
)

// accountEmailTimeout bounds the email step inside a callback. The step locks
// the deployment's account evidence stream, so a slow write gives up instead
// of using the time session issuance needs (S4c §3.1).
const accountEmailTimeout = 2 * time.Second

// ErrAccountEmailUnavailable reports a failed email write; sign-in goes on.
var ErrAccountEmailUnavailable = errors.New("oidcauth: account email unavailable")

// DisplayEmail returns the provider-verified email when Devices may show it
// (ValidDisplayEmail).
func DisplayEmail(profile Profile) (string, bool) {
	email := profile.Email()
	if !ValidDisplayEmail(email) {
		return "", false
	}
	return email, true
}

// ValidDisplayEmail reports an email Devices may show: one NewProfile keeps
// that also passes displayemail.Valid, the rule the database checks too.
func ValidDisplayEmail(email string) bool {
	return validProfileEmail(email) && displayemail.Valid(email)
}

// AccountEmail asks the store to record the verified email of the Account
// behind the exact consuming sign-in.
type AccountEmail struct {
	Lookup SubjectLookup
	Email  string
}

// String redacts the email.
func (AccountEmail) String() string { return "[REDACTED]" }

// LogValue redacts the email.
func (AccountEmail) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// AccountEmailResult says what the store did.
type AccountEmailResult uint8

const (
	// AccountEmailNoAccount means the identity has no active Account.
	AccountEmailNoAccount AccountEmailResult = iota + 1
	// AccountEmailUnchanged means the stored email already matches.
	AccountEmailUnchanged
	// AccountEmailRecorded means the email was written with its evidence.
	AccountEmailRecorded
)

// AccountEmailStore writes the email in one committed unit with evidence
// that never carries the email.
type AccountEmailStore interface {
	RecordEmail(ctx context.Context, email AccountEmail) (AccountEmailResult, error)
}

// AccountEmailOutcome is the closed metric label of one email step.
type AccountEmailOutcome uint8

const (
	// AccountEmailOutcomeSkipped means the provider sent no email Devices may show.
	AccountEmailOutcomeSkipped AccountEmailOutcome = iota + 1
	// AccountEmailOutcomeNoAccount means the identity has no Account yet.
	AccountEmailOutcomeNoAccount
	// AccountEmailOutcomeUnchanged means nothing was written.
	AccountEmailOutcomeUnchanged
	// AccountEmailOutcomeRecorded means a new email was written.
	AccountEmailOutcomeRecorded
	// AccountEmailOutcomeFailed means the write failed or timed out.
	AccountEmailOutcomeFailed
)

// String returns the metric label.
func (outcome AccountEmailOutcome) String() string {
	switch outcome {
	case AccountEmailOutcomeSkipped:
		return "skipped"
	case AccountEmailOutcomeNoAccount:
		return "no_account"
	case AccountEmailOutcomeUnchanged:
		return "unchanged"
	case AccountEmailOutcomeRecorded:
		return "recorded"
	case AccountEmailOutcomeFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// AccountEmailObserver counts email steps; it never sees the email.
type AccountEmailObserver interface {
	AccountEmailStep(outcome AccountEmailOutcome)
}

// recordEmail runs after the invitation or sign-up step and before subject
// resolution, on every callback that has a store. Its failure never fails the
// sign-in: the email is display data (S4c §3.1).
func (service *CallbackService) recordEmail(ctx context.Context, exchange ExchangeResult) {
	if service.emails == nil || service.subjectKeys == nil {
		return
	}
	service.observeEmail(service.writeEmail(ctx, exchange))
}

func (service *CallbackService) writeEmail(ctx context.Context, exchange ExchangeResult) AccountEmailOutcome {
	email, ok := DisplayEmail(exchange.identity.Profile())
	if !ok {
		return AccountEmailOutcomeSkipped
	}
	digests, err := service.subjectKeys.Digests(exchange.claimed.snapshot.Route(), exchange.identity)
	if err != nil {
		return AccountEmailOutcomeFailed
	}
	lookup, err := NewSubjectLookup(exchange.claimed, digests)
	if err != nil {
		return AccountEmailOutcomeFailed
	}
	timeout := service.emailTimeout
	if timeout <= 0 {
		timeout = accountEmailTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, err := service.emails.RecordEmail(ctx, AccountEmail{Lookup: lookup, Email: email})
	if err != nil {
		return AccountEmailOutcomeFailed
	}
	switch result {
	case AccountEmailNoAccount:
		return AccountEmailOutcomeNoAccount
	case AccountEmailUnchanged:
		return AccountEmailOutcomeUnchanged
	case AccountEmailRecorded:
		return AccountEmailOutcomeRecorded
	default:
		return AccountEmailOutcomeFailed
	}
}

func (service *CallbackService) observeEmail(outcome AccountEmailOutcome) {
	if service.emailObserver != nil {
		service.emailObserver.AccountEmailStep(outcome)
	}
}

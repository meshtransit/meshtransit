package oidcauth

import (
	"context"
	"errors"
	"log/slog"
)

var (
	// ErrSignupRejected reports a first sign-in that may not create an
	// Account: self sign-up is off for this deployment, the entitlement does
	// not allow it, or a sign-up limit is reached.
	ErrSignupRejected = errors.New("oidcauth: sign-up rejected")
	// ErrSignupUnavailable reports a dependency failure while signing up.
	ErrSignupUnavailable = errors.New("oidcauth: sign-up unavailable")
)

// signupFallbackName names an Account whose provider sent no profile.
const signupFallbackName = "MeshTransit user"

// SignupSource is a keyed digest of the network a first sign-in came from,
// used only to bound sign-ups per source. The zero value means unknown.
type SignupSource struct{ digest [32]byte }

// NewSignupSource wraps a source digest.
func NewSignupSource(digest [32]byte) SignupSource { return SignupSource{digest: digest} }

// IsValid reports a known source.
func (source SignupSource) IsValid() bool { return source.digest != [32]byte{} }

// Digest returns the digest the store counts.
func (source SignupSource) Digest() [32]byte { return source.digest }

// String redacts the digest.
func (SignupSource) String() string { return "[REDACTED]" }

// LogValue redacts the digest.
func (SignupSource) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// AccountSignup asks the store to give an identity with no Account one, owning
// a new default Workspace, bound to the exact consuming sign-in.
type AccountSignup struct {
	Lookup      SubjectLookup
	Source      SignupSource
	DisplayName string
}

// AccountSignupStore creates the Account and its Workspace in one committed
// unit when the identity has none, and does nothing when it has one.
type AccountSignupStore interface {
	SignUp(ctx context.Context, signup AccountSignup) error
}

// signUp runs between the exchange and subject resolution when the browser
// presented no invitation. A known identity passes through untouched.
func (service *CallbackService) signUp(ctx context.Context, exchange ExchangeResult, source SignupSource) error {
	if service.signups == nil || service.subjectKeys == nil {
		return nil
	}
	if !source.IsValid() {
		return ErrSignupRejected
	}
	digests, err := service.subjectKeys.Digests(exchange.claimed.snapshot.Route(), exchange.identity)
	if err != nil {
		return ErrSignupRejected
	}
	lookup, err := NewSubjectLookup(exchange.claimed, digests)
	if err != nil {
		return ErrSignupRejected
	}
	signup := AccountSignup{
		Lookup: lookup, Source: source, DisplayName: exchange.identity.Profile().DisplayName(signupFallbackName),
	}
	if err := service.signups.SignUp(ctx, signup); err != nil {
		if errors.Is(err, ErrSignupRejected) {
			return ErrSignupRejected
		}
		return ErrSignupUnavailable
	}
	return nil
}

package oidcauth

import (
	"context"
	"crypto/hmac"
	"errors"
	"log/slog"
	"time"
)

var (
	// ErrInvalidBrowserVerification reports invalid setup without dependency effects.
	ErrInvalidBrowserVerification = errors.New("oidc auth: invalid browser verification")
	// ErrBrowserVerificationRejected conceals absent, expired, or invalid proof details.
	ErrBrowserVerificationRejected = errors.New("oidc auth: browser verification rejected")
	// ErrBrowserVerificationUnavailable classifies failed reads without dependency text.
	ErrBrowserVerificationUnavailable = errors.New("oidc auth: browser verification unavailable")
)

// PendingLoader owns a bounded read-only unit and joins all cleanup before return.
// Positive evidence is not a claim, session, or durable revocation lease.
type PendingLoader interface {
	// LoadPending selects exact current browser-login evidence by a keyed state digest.
	// It returns no positive evidence on read completion or cleanup failure.
	LoadPending(context.Context, Route, Digest) (PendingSnapshot, bool, error)
}

// BrowserVerificationOptions bounds the entire read/crypto/release operation.
type BrowserVerificationOptions struct{ RequestTimeout time.Duration }

// BrowserVerificationDependencies uses resident exact-generation keys; no fallback
// key lookup, discovery, or provider token exchange occurs inside this use case.
type BrowserVerificationDependencies struct {
	Pending        PendingLoader
	DigestKey      DigestKey
	VerifierCipher *VerifierCipher
	Clock          StartClock
}

// BrowserVerificationService verifies browser possession without consuming state.
// It stores no request context and creates no goroutines or provider credentials.
type BrowserVerificationService struct {
	options      BrowserVerificationOptions
	dependencies BrowserVerificationDependencies
}

// NewBrowserVerificationService rejects invalid dependencies before any I/O.
func NewBrowserVerificationService(options BrowserVerificationOptions, dependencies BrowserVerificationDependencies) (*BrowserVerificationService, error) {
	if options.RequestTimeout <= 0 || options.RequestTimeout > 30*time.Second ||
		dependencies.Pending == nil || dependencies.Clock == nil || !dependencies.DigestKey.isValid() ||
		dependencies.VerifierCipher == nil || !dependencies.VerifierCipher.ID().IsValid() ||
		dependencies.VerifierCipher.aead == nil {
		return nil, ErrInvalidBrowserVerification
	}
	return &BrowserVerificationService{options: options, dependencies: dependencies}, nil
}

// VerifyBrowser checks purpose-separated state, full creation hash, browser AEAD,
// and cookie possession after the loader has closed its unit. Its opaque result
// cannot release a PKCE verifier; only a future confirmed single-use claim may do so.
func (service *BrowserVerificationService) VerifyBrowser(ctx context.Context, route Route, state State, cookie PreAuthCookie) (VerifiedBrowser, error) {
	if ctx == nil || service == nil || service.dependencies.Pending == nil ||
		service.dependencies.Clock == nil || service.options.RequestTimeout <= 0 ||
		service.options.RequestTimeout > 30*time.Second || !route.IsValid() ||
		!state.IsValid() || !cookie.IsValid() {
		return VerifiedBrowser{}, ErrInvalidBrowserVerification
	}
	ctx, cancel := context.WithTimeout(ctx, service.options.RequestTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return VerifiedBrowser{}, errors.Join(ErrBrowserVerificationRejected, err)
	}
	digest, err := service.dependencies.DigestKey.State(route.DeploymentID(), route.RecoveryEpoch(), state)
	if err != nil {
		return VerifiedBrowser{}, ErrBrowserVerificationRejected
	}
	snapshot, found, err := service.dependencies.Pending.LoadPending(ctx, route, digest)
	if err != nil {
		return VerifiedBrowser{}, errors.Join(ErrBrowserVerificationUnavailable, ctx.Err())
	}
	if err := ctx.Err(); err != nil {
		return VerifiedBrowser{}, errors.Join(ErrBrowserVerificationRejected, err)
	}
	if !found || !snapshot.MatchesRoute(route) || !livePendingSnapshotAtLocalClock(snapshot, service.dependencies.Clock.Now()) {
		return VerifiedBrowser{}, ErrBrowserVerificationRejected
	}
	expected, actual := snapshot.StateDigest().Bytes(), digest.Bytes()
	if snapshot.StateDigest().KeyID() != digest.KeyID() || !hmac.Equal(expected[:], actual[:]) {
		return VerifiedBrowser{}, ErrBrowserVerificationRejected
	}
	binding, err := route.Binding(snapshot.TransactionID())
	if err != nil {
		return VerifiedBrowser{}, ErrBrowserVerificationRejected
	}
	proof, err := service.dependencies.VerifierCipher.OpenBrowser(binding, snapshot.VerifierCiphertext())
	if err != nil || !service.dependencies.DigestKey.VerifyPreAuthCookie(binding, cookie, proof.CookieDigest()) {
		return VerifiedBrowser{}, ErrBrowserVerificationRejected
	}
	if !livePendingSnapshotAtLocalClock(snapshot, service.dependencies.Clock.Now()) {
		return VerifiedBrowser{}, ErrBrowserVerificationRejected
	}
	if err := ctx.Err(); err != nil {
		return VerifiedBrowser{}, errors.Join(ErrBrowserVerificationRejected, err)
	}
	return VerifiedBrowser{snapshot: snapshot, cookieDigest: proof.CookieDigest()}, nil
}

func livePendingSnapshot(snapshot PendingSnapshot, now time.Time) bool {
	return !now.Before(snapshot.CreatedAt()) && now.Before(snapshot.ExpiresAt())
}

func livePendingSnapshotAtLocalClock(snapshot PendingSnapshot, now time.Time) bool {
	return authorityTimeReached(now, snapshot.CreatedAt()) && now.Before(snapshot.ExpiresAt())
}

// VerifiedBrowser is opaque possession evidence, deliberately not an exchange grant.
// Concurrent read verification may succeed more than once; pending -> consuming
// must still be atomically claimed with current authority and audit/outbox.
type VerifiedBrowser struct {
	snapshot     PendingSnapshot
	cookieDigest CookieDigest
}

// Snapshot returns immutable evidence needed for a later locked claim, not PKCE.
func (verified VerifiedBrowser) Snapshot() PendingSnapshot { return verified.snapshot }

// IsValid checks possession evidence shape, not live durable authority.
func (verified VerifiedBrowser) IsValid() bool {
	return verified.snapshot.IsValid() && verified.cookieDigest.IsValid()
}

// String prevents accidental possession-evidence disclosure.
func (VerifiedBrowser) String() string { return "[REDACTED]" }

// GoString prevents accidental detailed possession-evidence disclosure.
func (VerifiedBrowser) GoString() string { return "oidcauth.VerifiedBrowser([REDACTED])" }

// LogValue prevents accidental structured-log possession-evidence disclosure.
func (VerifiedBrowser) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

package oidcauth

import (
	"context"
	"crypto/hmac"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"
)

var (
	// ErrInvalidExchange rejects unsafe construction or absent confirmed evidence.
	ErrInvalidExchange = errors.New("oidc auth: invalid browser exchange")
	// ErrExchangeRejected conceals exhausted, expired, or mismatched authentication.
	ErrExchangeRejected = errors.New("oidc auth: browser exchange rejected")
	// ErrExchangeUnavailable conceals back-channel dependency failure.
	ErrExchangeUnavailable = errors.New("oidc auth: browser exchange unavailable")
	// ErrExchangeLimited rejects excess work without queueing or provider I/O.
	ErrExchangeLimited = errors.New("oidc auth: browser exchange limited")
)

// Code is bounded opaque authorization-code material, never identity or telemetry.
type Code struct{ value string }

// ParseCode accepts nonempty printable ASCII within a 4096-byte callback budget.
func ParseCode(value string) (Code, error) {
	if !validBoundedToken(value, 4096) {
		return Code{}, ErrInvalidExchange
	}
	return Code{value: value}, nil
}

// IsValid rejects an absent or malformed code before any dependency effects.
func (code Code) IsValid() bool { return validBoundedToken(code.value, 4096) }

// Encoded releases code only to the fixed server-side token endpoint.
func (code Code) Encoded() string { return code.value }

// String redacts authorization-code material.
func (Code) String() string { return "[REDACTED]" }

// GoString redacts detailed code formatting.
func (Code) GoString() string { return "oidcauth.Code([REDACTED])" }

// LogValue redacts structured code formatting.
func (Code) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// ExchangeRequest is created only inside ExchangeService after burning one
// confirmed attempt. Its explicit secret accessors belong to the trusted port,
// never a public handler, receipt, error, or session API.
type ExchangeRequest struct {
	claimed  Claimed
	code     Code
	verifier Verifier
}

// Route returns only the original independently allowlisted trust configuration.
func (request ExchangeRequest) Route() Route { return request.claimed.snapshot.Route() }

// Code releases original callback material only to the provider port.
func (request ExchangeRequest) Code() Code { return request.code }

// Verifier releases recovered original PKCE only to the provider port.
func (request ExchangeRequest) Verifier() Verifier { return request.verifier }

// IsValid checks request shape, not a reusable public exchange grant.
func (request ExchangeRequest) IsValid() bool {
	return request.claimed.IsValid() && request.code.IsValid() && request.verifier.IsValid()
}

// String redacts back-channel material.
func (ExchangeRequest) String() string { return "[REDACTED]" }

// GoString redacts detailed back-channel formatting.
func (ExchangeRequest) GoString() string { return "oidcauth.ExchangeRequest([REDACTED])" }

// LogValue redacts structured back-channel formatting.
func (ExchangeRequest) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

// TokenAuthenticator exchanges code once and validates ID-token signature and
// exact route/client/time/key policy before returning evidence. Implementations
// must bound TLS/JSON/JWKS work, never retry POST or follow token-selected URLs,
// and never release provider tokens or raw errors. Nonce HMAC remains Core-owned.
type TokenAuthenticator interface {
	Authenticate(context.Context, ExchangeRequest) (TokenEvidence, error)
}

// ExchangeOptions bounds complete work and rejects concurrent excess without queueing.
type ExchangeOptions struct {
	RequestTimeout time.Duration
	MaxConcurrent  int
}

// ExchangeDependencies names only resident crypto, provider I/O, and a live clock.
// No database unit, resolver, session, or membership mutation is part of exchange.
type ExchangeDependencies struct {
	Provider  TokenAuthenticator
	Cipher    *VerifierCipher
	DigestKey DigestKey
	Clock     StartClock
}

// ExchangeService owns one bounded back-channel attempt; no goroutines or sticky
// state are required for durable claim correctness. Session issuance is separate.
type ExchangeService struct {
	options      ExchangeOptions
	dependencies ExchangeDependencies
	active       chan struct{}
}

// NewExchangeService rejects incomplete security dependencies before effects.
func NewExchangeService(options ExchangeOptions, dependencies ExchangeDependencies) (*ExchangeService, error) {
	validBudget := options.RequestTimeout > 0 && options.RequestTimeout <= 30*time.Second && options.MaxConcurrent > 0 && options.MaxConcurrent <= 256
	validCipher := dependencies.Cipher != nil && dependencies.Cipher.ID().IsValid() && dependencies.Cipher.aead != nil
	if !validBudget || !validCipher || !dependencies.DigestKey.isValid() || dependencies.Provider == nil || dependencies.Clock == nil {
		return nil, ErrInvalidExchange
	}
	return &ExchangeService{options: options, dependencies: dependencies, active: make(chan struct{}, options.MaxConcurrent)}, nil
}

// ExchangeBrowser burns a confirmed receipt before crypto/provider work, including
// on failure. Copies cannot retry. Check cancellation/live claim before effects and
// again before releasing opaque exact-subject evidence, never a Core session.
func (service *ExchangeService) ExchangeBrowser(ctx context.Context, receipt ClaimResult, code Code) (ExchangeResult, error) {
	if ctx == nil || service == nil || service.active == nil || !receipt.IsValid() || !code.IsValid() {
		return ExchangeResult{}, ErrInvalidExchange
	}
	ctx, cancel := context.WithTimeout(ctx, service.options.RequestTimeout)
	defer cancel()
	if ctx.Err() != nil || !liveClaimAtLocalClock(receipt.claimed, service.dependencies.Clock.Now()) {
		return ExchangeResult{}, errors.Join(ErrExchangeRejected, ctx.Err())
	}
	if !receipt.exchangeAttempt.CompareAndSwap(false, true) {
		return ExchangeResult{}, ErrExchangeRejected
	}
	select {
	case service.active <- struct{}{}:
		defer func() { <-service.active }()
	default:
		return ExchangeResult{}, ErrExchangeLimited
	}
	claimed := receipt.claimed
	binding, err := claimed.snapshot.Route().Binding(claimed.TransactionID())
	if err != nil {
		return ExchangeResult{}, ErrExchangeRejected
	}
	proof, err := service.dependencies.Cipher.OpenBrowser(binding, claimed.snapshot.VerifierCiphertext())
	if err != nil || !proof.IsValid() || ctx.Err() != nil || !liveClaimAtLocalClock(claimed, service.dependencies.Clock.Now()) {
		return ExchangeResult{}, errors.Join(ErrExchangeRejected, ctx.Err())
	}
	evidence, err := service.dependencies.Provider.Authenticate(ctx, ExchangeRequest{claimed: claimed, code: code, verifier: proof.Verifier()})
	if err != nil {
		return ExchangeResult{}, errors.Join(ErrExchangeUnavailable, ctx.Err())
	}
	if !evidence.IsValid() || evidence.Issuer() != claimed.snapshot.Route().Issuer() {
		return ExchangeResult{}, ErrExchangeRejected
	}
	digest, err := service.dependencies.DigestKey.Nonce(binding.DeploymentID, binding.RecoveryEpoch, evidence.nonce)
	expected := claimed.snapshot.NonceDigest()
	actualBytes, expectedBytes := digest.Bytes(), expected.Bytes()
	if err != nil || digest.KeyID() != expected.KeyID() || !hmac.Equal(actualBytes[:], expectedBytes[:]) {
		return ExchangeResult{}, ErrExchangeRejected
	}
	now := service.dependencies.Clock.Now()
	if ctx.Err() != nil || !liveClaimAtLocalClock(claimed, now) || !now.Before(evidence.ExpiresAt()) {
		return ExchangeResult{}, errors.Join(ErrExchangeRejected, ctx.Err())
	}
	return ExchangeResult{claimed: claimed, identity: evidence.identity, issuanceAttempt: &atomic.Bool{}}, nil
}
func liveClaim(claimed Claimed, now time.Time) bool {
	return !now.Before(claimed.ConsumedAt()) && livePendingSnapshot(claimed.snapshot, now)
}

func liveClaimAtLocalClock(claimed Claimed, now time.Time) bool {
	return authorityTimeReached(now, claimed.ConsumedAt()) && livePendingSnapshotAtLocalClock(claimed.snapshot, now)
}

// ExchangeResult is opaque validated authentication, not session/admission authority.
type ExchangeResult struct {
	claimed         Claimed
	identity        ExternalIdentity
	issuanceAttempt *atomic.Bool
}

// IsValid checks immutable result shape, not current provider/membership authority.
func (result ExchangeResult) IsValid() bool {
	return result.claimed.IsValid() && result.identity.IsValid() && result.issuanceAttempt != nil
}

// Identity explicitly releases exact validated subject evidence for Core resolution.
// Never serialize or log it; email/roles/groups are deliberately absent.
func (result ExchangeResult) Identity() ExternalIdentity { return result.identity }

// Claimed returns original transition evidence for later locked session issuance.
func (result ExchangeResult) Claimed() Claimed { return result.claimed }

// String redacts identity evidence.
func (ExchangeResult) String() string { return "[REDACTED]" }

// GoString redacts detailed identity evidence.
func (ExchangeResult) GoString() string { return "oidcauth.ExchangeResult([REDACTED])" }

// LogValue redacts structured identity evidence.
func (ExchangeResult) LogValue() slog.Value { return slog.StringValue("[REDACTED]") }

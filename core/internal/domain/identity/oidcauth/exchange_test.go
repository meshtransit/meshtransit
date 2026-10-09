package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func TestExchangeBrowserConsumesReceiptAcrossCopies(t *testing.T) {
	t.Parallel()
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	verified := claimVerifiedFixture(t)
	now := verified.Snapshot().CreatedAt().Add(time.Second)
	claim, err := NewClaimService(ClaimOptions{RequestTimeout: time.Second, RollbackTimeout: time.Second}, ClaimDependencies{
		Transactions: &claimTestTransactions{unit: &claimTestUnit{now: now}}, IDs: SystemClaimIDs{}, Clock: browserVerificationClock{now: func() time.Time { return now }},
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := claim.ClaimBrowser(t.Context(), verified)
	if err != nil {
		t.Fatal(err)
	}
	params := pendingParamsFixture(t)
	var calls atomic.Int64
	entered, release := make(chan struct{}), make(chan struct{})
	provider := exchangeTestProvider{authenticate: func(ctx context.Context, request ExchangeRequest) (TokenEvidence, error) {
		calls.Add(1)
		if request.Verifier().Encoded() != params.Secrets.Verifier().Encoded() || !request.IsValid() {
			t.Error("original verifier not preserved")
		}
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return TokenEvidence{}, ctx.Err()
		}
		return NewTokenEvidence(TokenEvidenceParams{Issuer: params.Route.Issuer(), Subject: "Opaque-Subject", Nonce: params.Secrets.Nonce(), IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
	}}
	service, err := NewExchangeService(ExchangeOptions{RequestTimeout: time.Second, MaxConcurrent: 1}, ExchangeDependencies{Provider: provider, Cipher: params.VerifierCipher, DigestKey: params.DigestKey, Clock: browserVerificationClock{now: func() time.Time { return now }}})
	if err != nil {
		t.Fatal(err)
	}
	code, err := ParseCode("synthetic-code")
	if err != nil {
		t.Fatal(err)
	}
	var ownerResult ExchangeResult
	var ownerErr error
	var owner sync.WaitGroup
	owner.Go(func() { ownerResult, ownerErr = service.ExchangeBrowser(t.Context(), receipt, code) })
	<-entered
	copyReceipt := receipt
	if result, err := service.ExchangeBrowser(t.Context(), copyReceipt, code); err == nil || result.IsValid() {
		t.Error("copied receipt reused")
	}
	close(release)
	owner.Wait()
	if ownerErr != nil || !ownerResult.IsValid() || calls.Load() != 1 {
		t.Fatalf("single exchange failed: %v", ownerErr)
	}
	if fmt.Sprint(ownerResult) != "[REDACTED]" || ownerResult.Identity().Subject() != "Opaque-Subject" {
		t.Fatal("identity or redaction lost")
	}
	if result, err := service.ExchangeBrowser(t.Context(), receipt, code); err == nil || result.IsValid() {
		t.Fatal("completed receipt reused")
	}
}

func TestExchangeBrowserFailureBurnsAttempt(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"provider error", "wrong nonce", "wrong issuer", "expired after provider", "canceled after provider", "wrong cipher"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			verified := claimVerifiedFixture(t)
			now := verified.Snapshot().CreatedAt().Add(time.Second)
			claim, err := NewClaimService(ClaimOptions{RequestTimeout: time.Second, RollbackTimeout: time.Second}, ClaimDependencies{Transactions: &claimTestTransactions{unit: &claimTestUnit{now: now}}, IDs: SystemClaimIDs{}, Clock: browserVerificationClock{now: func() time.Time { return now }}})
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := claim.ClaimBrowser(t.Context(), verified)
			if err != nil {
				t.Fatal(err)
			}
			params := pendingParamsFixture(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			calls := 0
			dependencies := ExchangeDependencies{Cipher: params.VerifierCipher, DigestKey: params.DigestKey, Clock: browserVerificationClock{now: func() time.Time { return now }}, Provider: exchangeTestProvider{authenticate: func(context.Context, ExchangeRequest) (TokenEvidence, error) {
				calls++
				if name == "provider error" {
					return TokenEvidence{}, errors.New("private provider credential failure")
				}
				issuer, nonce := params.Route.Issuer(), params.Secrets.Nonce()
				if name == "wrong nonce" {
					nonce = Nonce{value: [32]byte{1}}
				}
				if name == "wrong issuer" {
					issuer += "/alias"
				}
				if name == "canceled after provider" {
					cancel()
				}
				evidence, err := NewTokenEvidence(TokenEvidenceParams{Issuer: issuer, Subject: "opaque", Nonce: nonce, IssuedAt: now, ExpiresAt: now.Add(time.Minute)})
				if name == "expired after provider" {
					now = verified.Snapshot().ExpiresAt()
				}
				return evidence, err
			}}}
			if name == "wrong cipher" {
				dependencies.Cipher, err = NewVerifierCipher(params.VerifierCipher.ID(), makeNonZeroVerificationBytes())
				if err != nil {
					t.Fatal(err)
				}
			}
			service, err := NewExchangeService(ExchangeOptions{RequestTimeout: time.Second, MaxConcurrent: 1}, dependencies)
			if err != nil {
				t.Fatal(err)
			}
			code, err := ParseCode("synthetic-code")
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.ExchangeBrowser(ctx, receipt, code)
			if err == nil || result.IsValid() {
				t.Fatal("failed exchange released evidence")
			}
			if result, err := service.ExchangeBrowser(t.Context(), receipt, code); err == nil || result.IsValid() {
				t.Fatal("failed attempt replayed")
			}
			if calls > 1 || name == "wrong cipher" && calls != 0 {
				t.Fatal("provider retried or called before AEAD validation")
			}
		})
	}
}

func FuzzParseCode(f *testing.F) {
	f.Add("synthetic-code")
	f.Add("")
	f.Add("code\r\n")
	f.Fuzz(func(t *testing.T, input string) {
		code, err := ParseCode(input)
		if err == nil && (!code.IsValid() || code.Encoded() != input || fmt.Sprint(code) != "[REDACTED]") {
			t.Fatal("code invariant violated")
		}
	})
}

type exchangeTestProvider struct {
	authenticate func(context.Context, ExchangeRequest) (TokenEvidence, error)
}

func (provider exchangeTestProvider) Authenticate(ctx context.Context, request ExchangeRequest) (TokenEvidence, error) {
	return provider.authenticate(ctx, request)
}

package oidcauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestBrowserVerificationChecksLoadedProofWithoutExchangeGrant(t *testing.T) {
	t.Parallel()
	params := pendingParamsFixture(t)
	snapshot, err := NewPendingSnapshot(snapshotParamsFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	loader := browserVerificationLoader{load: func(ctx context.Context, route Route, digest Digest) (PendingSnapshot, bool, error) {
		if _, ok := ctx.Deadline(); !ok || digest.Bytes() != snapshot.StateDigest().Bytes() ||
			route.ProviderID() != snapshot.Route().ProviderID() {
			t.Fatal("unbounded or mismatched lookup")
		}
		return snapshot, true, nil
	}}
	service, err := NewBrowserVerificationService(BrowserVerificationOptions{RequestTimeout: time.Second}, BrowserVerificationDependencies{
		Pending: loader, DigestKey: params.DigestKey, VerifierCipher: params.VerifierCipher,
		Clock: browserVerificationClock{now: func() time.Time { return snapshot.CreatedAt().Add(time.Second) }},
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := service.VerifyBrowser(context.Background(), params.Route, params.Secrets.State(), params.Secrets.PreAuthCookie())
	if err != nil || !verified.IsValid() || verified.Snapshot().SemanticHash() != snapshot.SemanticHash() {
		t.Fatalf("VerifyBrowser() error = %v", err)
	}
	if fmt.Sprint(verified) != "[REDACTED]" || verified.LogValue().String() != "[REDACTED]" {
		t.Fatal("verified browser proof disclosed material")
	}
}

func TestBrowserVerificationFailsClosedAcrossReadAndRelease(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"missing", "malformed", "read error", "wrong state", "wrong cookie", "wrong resident key", "wrong cipher material", "tampered authenticated envelope", "expired", "future creation", "expired after verification", "canceled after read", "canceled at release"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			params := pendingParamsFixture(t)
			snapshot, err := NewPendingSnapshot(snapshotParamsFixture(t))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			state, cookie := params.Secrets.State(), params.Secrets.PreAuthCookie()
			clockCalls := 0
			dependencies := BrowserVerificationDependencies{
				DigestKey: params.DigestKey, VerifierCipher: params.VerifierCipher,
				Clock: browserVerificationClock{now: func() time.Time {
					clockCalls++
					if name == "canceled at release" && clockCalls > 1 {
						cancel()
					}
					if name == "expired" || (name == "expired after verification" && clockCalls > 1) {
						return snapshot.ExpiresAt()
					}
					if name == "future creation" {
						return snapshot.CreatedAt().Add(-authorityClockSkewAllowance - time.Second)
					}
					return snapshot.CreatedAt().Add(time.Second)
				}},
				Pending: browserVerificationLoader{load: func(context.Context, Route, Digest) (PendingSnapshot, bool, error) {
					switch name {
					case "missing":
						return PendingSnapshot{}, false, nil
					case "malformed":
						return PendingSnapshot{}, true, nil
					case "read error":
						return snapshot, true, errors.New("synthetic unavailable dependency")
					case "canceled after read":
						cancel()
					}
					return snapshot, true, nil
				}},
			}
			switch name {
			case "wrong state":
				state = State{value: [32]byte{1}}
			case "wrong cookie":
				cookie = PreAuthCookie{value: [32]byte{1}}
			case "wrong resident key":
				dependencies.DigestKey, _ = NewDigestKey(params.DigestKey.ID(), makeNonZeroVerificationBytes())
			case "wrong cipher material":
				dependencies.VerifierCipher, err = newVerifierCipher(params.VerifierCipher.ID(), makeNonZeroVerificationBytes(), bytes.NewReader(nil))
				if err != nil {
					t.Fatal(err)
				}
			case "tampered authenticated envelope":
				value := snapshot.pending.verifierCiphertext.Bytes()
				value[len(value)-1] ^= 1
				snapshot.pending.verifierCiphertext, err = NewCiphertext(snapshot.pending.verifierCiphertext.KeyID(), value)
				if err != nil {
					t.Fatal(err)
				}
				// Public hash recomputation alone cannot authenticate encrypted proof.
				snapshot.pending.semanticHash = hashPending(snapshot.pending)
				if !snapshot.IsValid() {
					t.Fatal("tamper test did not reach AEAD boundary")
				}
			}
			service, err := NewBrowserVerificationService(BrowserVerificationOptions{RequestTimeout: time.Second}, dependencies)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := service.VerifyBrowser(ctx, params.Route, state, cookie)
			if err == nil || verified.IsValid() {
				t.Fatal("invalid verification released proof")
			}
		})
	}
}

func TestBrowserVerificationRejectsInvalidSetupBeforeLookup(t *testing.T) {
	t.Parallel()
	if _, err := NewBrowserVerificationService(BrowserVerificationOptions{}, BrowserVerificationDependencies{}); !errors.Is(err, ErrInvalidBrowserVerification) {
		t.Fatal("invalid verification service accepted")
	}
	var service *BrowserVerificationService
	if _, err := service.VerifyBrowser(t.Context(), Route{}, State{}, PreAuthCookie{}); err == nil {
		t.Fatal("nil service accepted")
	}
	params := pendingParamsFixture(t)
	service, err := NewBrowserVerificationService(BrowserVerificationOptions{RequestTimeout: time.Second}, BrowserVerificationDependencies{
		Pending: browserVerificationLoader{load: func(context.Context, Route, Digest) (PendingSnapshot, bool, error) {
			t.Fatal("invalid caller reached lookup")
			return PendingSnapshot{}, false, nil
		}}, DigestKey: params.DigestKey, VerifierCipher: params.VerifierCipher,
		Clock: browserVerificationClock{now: func() time.Time { return params.CreatedAt }},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The absent context interface deliberately tests the boundary rejection,
	// matching login-start tests, before any context operation or lookup.
	var absentContext context.Context
	if _, err := service.VerifyBrowser(absentContext, params.Route, params.Secrets.State(), params.Secrets.PreAuthCookie()); !errors.Is(err, ErrInvalidBrowserVerification) {
		t.Fatal("absent context accepted")
	}
}

type browserVerificationLoader struct {
	load func(context.Context, Route, Digest) (PendingSnapshot, bool, error)
}

func (loader browserVerificationLoader) LoadPending(ctx context.Context, route Route, digest Digest) (PendingSnapshot, bool, error) {
	return loader.load(ctx, route, digest)
}

type browserVerificationClock struct{ now func() time.Time }

func (clock browserVerificationClock) Now() time.Time { return clock.now() }
func makeNonZeroVerificationBytes() []byte {
	value := make([]byte, 32)
	for index := range value {
		value[index] = 0x91
	}
	return value
}

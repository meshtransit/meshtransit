package oidcauth

import (
	"context"
	"errors"
	"slices"
	"testing"
)

type signupTestStore struct {
	fixture *callbackFixture
	err     error
	signup  AccountSignup
	calls   int
}

func (store *signupTestStore) SignUp(_ context.Context, signup AccountSignup) error {
	store.fixture.effects = append(store.fixture.effects, "signup")
	store.signup = signup
	store.calls++
	return store.err
}

func withSignups(t *testing.T, fixture *callbackFixture, store AccountSignupStore, invitations InvitationAcceptor) {
	t.Helper()
	fixture.deps.Signups = store
	fixture.deps.Invitations = invitations
	service, err := NewCallbackService(fixture.options, fixture.deps)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = service
}

func TestCallbackSignsUpBeforeResolvingTheSubject(t *testing.T) {
	t.Parallel()
	fixture := newCallbackFixture(t)
	store := &signupTestStore{fixture: fixture}
	withSignups(t, fixture, store, nil)
	command, err := fixture.command.WithSignupSource(NewSignupSource([32]byte{9}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := fixture.service.CompleteBrowser(t.Context(), command)
	if err != nil || !result.Issued().IsValid() {
		t.Fatalf("CompleteBrowser() = %v", err)
	}
	signup, resolve := slices.Index(fixture.effects, "signup"), slices.Index(fixture.effects, "resolve")
	if exchange := slices.Index(fixture.effects, "exchange"); exchange < 0 || signup <= exchange || resolve <= signup {
		t.Fatalf("effects = %v, want exchange, signup, resolve", fixture.effects)
	}
	if !store.signup.Lookup.IsValid() || store.signup.Source.Digest() != [32]byte{9} ||
		store.signup.DisplayName != signupFallbackName {
		t.Fatalf("signup = %+v", store.signup)
	}
}

func TestCallbackRefusesASignUpItCannotBound(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		err    error
		source bool
	}{
		"rejected":       {err: ErrSignupRejected, source: true},
		"unavailable":    {err: errors.New("private database detail"), source: true},
		"unknown source": {},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newCallbackFixture(t)
			store := &signupTestStore{fixture: fixture, err: test.err}
			withSignups(t, fixture, store, nil)
			command := fixture.command
			if test.source {
				var err error
				if command, err = command.WithSignupSource(NewSignupSource([32]byte{9})); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := fixture.service.CompleteBrowser(t.Context(), command); err == nil {
				t.Fatal("a refused sign-up must not issue a Session")
			}
			if slices.Contains(fixture.effects, "resolve") || slices.Contains(fixture.effects, "issue") {
				t.Fatalf("effects = %v, want no resolution or issuance", fixture.effects)
			}
		})
	}
}

func TestCallbackSkipsSignUpForAnInvitationOrWhenOff(t *testing.T) {
	t.Parallel()
	fixture := newCallbackFixture(t)
	store := &signupTestStore{fixture: fixture}
	withSignups(t, fixture, store, &invitationTestAcceptor{fixture: fixture})
	command, err := fixture.command.WithInvitation(NewInvitationProof([32]byte{7}))
	if err != nil {
		t.Fatal(err)
	}
	if command, err = command.WithSignupSource(NewSignupSource([32]byte{9})); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.CompleteBrowser(t.Context(), command); err != nil || store.calls != 0 {
		t.Fatalf("an invitation sign-in signed up: calls=%d err=%v", store.calls, err)
	}
	off := newCallbackFixture(t)
	if _, err := off.service.CompleteBrowser(t.Context(), off.command); err != nil {
		t.Fatalf("with sign-up off a known identity must still sign in: %v", err)
	}
}

func TestSignupSourceIsRedactedAndRequired(t *testing.T) {
	t.Parallel()
	fixture := newCallbackFixture(t)
	if _, err := fixture.command.WithSignupSource(SignupSource{}); err == nil {
		t.Fatal("an empty source must be refused")
	}
	source := NewSignupSource([32]byte{1})
	if source.String() != "[REDACTED]" || source.LogValue().String() != "[REDACTED]" {
		t.Fatal("a source must never print")
	}
}

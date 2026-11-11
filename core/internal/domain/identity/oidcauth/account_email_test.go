package oidcauth

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

type emailTestStore struct {
	fixture *callbackFixture
	result  AccountEmailResult
	err     error
	stall   bool
	email   AccountEmail
	calls   int
}

func (store *emailTestStore) RecordEmail(ctx context.Context, email AccountEmail) (AccountEmailResult, error) {
	store.fixture.effects = append(store.fixture.effects, "email")
	store.email = email
	store.calls++
	if store.stall {
		<-ctx.Done()
		return 0, ctx.Err()
	}
	return store.result, store.err
}

type emailTestObserver struct {
	mutex    sync.Mutex
	outcomes []AccountEmailOutcome
}

func (observer *emailTestObserver) AccountEmailStep(outcome AccountEmailOutcome) {
	observer.mutex.Lock()
	defer observer.mutex.Unlock()
	observer.outcomes = append(observer.outcomes, outcome)
}

func withEmails(t *testing.T, fixture *callbackFixture, store AccountEmailStore, observer AccountEmailObserver,
	signups AccountSignupStore, invitations InvitationAcceptor,
) {
	t.Helper()
	fixture.deps.Emails, fixture.deps.EmailObserver = store, observer
	fixture.deps.Signups, fixture.deps.Invitations = signups, invitations
	service, err := NewCallbackService(fixture.options, fixture.deps)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = service
}

func TestDisplayEmailKeepsOnlyPrintableASCII(t *testing.T) {
	t.Parallel()
	for email, want := range map[string]bool{
		"person@example.test":                 true,
		"a.b+c@example.test":                  true,
		"":                                    false,
		"no-at.example.test":                  false,
		"two@at@example.test":                 false,
		"@example.test":                       false,
		"user@":                               false,
		"user@exämple.test":                   false,
		"üser@example.test":                   false,
		"user\u00a0x@example.test":            false,
		"user\u202e@example.test":             false,
		"user<x@example.test":                 false,
		"user>x@example.test":                 false,
		"user\"x@example.test":                false,
		"user x@example.test":                 false,
		strings.Repeat("a", 250) + "@ex.test": false,
		strings.Repeat("a", 240) + "@ex.test": true,
		"user@localhost":                      false, // NewProfile wants a dot in the domain
	} {
		got, ok := DisplayEmail(NewProfile("", email))
		if ok != want || (ok && got != email) {
			t.Errorf("DisplayEmail(%q) = %q, %t; want %t", email, got, ok, want)
		}
	}
}

func TestCallbackRecordsEmailAfterSignUpAndBeforeResolution(t *testing.T) {
	t.Parallel()
	fixture := newCallbackFixture(t)
	fixture.providerEmail = "person@example.test"
	store := &emailTestStore{fixture: fixture, result: AccountEmailRecorded}
	observer := &emailTestObserver{}
	withEmails(t, fixture, store, observer, &signupTestStore{fixture: fixture}, nil)
	command, err := fixture.command.WithSignupSource(NewSignupSource([32]byte{9}))
	if err != nil {
		t.Fatal(err)
	}
	result, err := fixture.service.CompleteBrowser(t.Context(), command)
	if err != nil || !result.Issued().IsValid() {
		t.Fatalf("CompleteBrowser() = %v", err)
	}
	signup, email, resolve := slices.Index(fixture.effects, "signup"), slices.Index(fixture.effects, "email"),
		slices.Index(fixture.effects, "resolve")
	if signup < 0 || email <= signup || resolve <= email {
		t.Fatalf("effects = %v, want signup, email, resolve", fixture.effects)
	}
	if store.email.Email != "person@example.test" || !store.email.Lookup.IsValid() {
		t.Fatalf("email step got %v", store.email)
	}
	if !slices.Equal(observer.outcomes, []AccountEmailOutcome{AccountEmailOutcomeRecorded}) {
		t.Fatalf("outcomes = %v", observer.outcomes)
	}
}

func TestCallbackRecordsEmailForAnInvitation(t *testing.T) {
	t.Parallel()
	fixture := newCallbackFixture(t)
	fixture.providerEmail = "invited@example.test"
	store := &emailTestStore{fixture: fixture, result: AccountEmailRecorded}
	withEmails(t, fixture, store, nil, nil, &invitationTestAcceptor{fixture: fixture})
	command, err := fixture.command.WithInvitation(NewInvitationProof([32]byte{7}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.CompleteBrowser(t.Context(), command); err != nil {
		t.Fatalf("CompleteBrowser() = %v", err)
	}
	accept, email := slices.Index(fixture.effects, "accept"), slices.Index(fixture.effects, "email")
	if accept < 0 || email <= accept || store.email.Email != "invited@example.test" {
		t.Fatalf("effects = %v email = %v", fixture.effects, store.email)
	}
}

func TestCallbackRecordsEmailWithSignUpOff(t *testing.T) {
	t.Parallel()
	fixture := newCallbackFixture(t)
	fixture.providerEmail = "selfhost@example.test"
	store := &emailTestStore{fixture: fixture, result: AccountEmailUnchanged}
	withEmails(t, fixture, store, nil, nil, nil)
	if _, err := fixture.service.CompleteBrowser(t.Context(), fixture.command); err != nil || store.calls != 1 {
		t.Fatalf("self-host must record the email: calls=%d err=%v", store.calls, err)
	}
}

// Not parallel: a stalled step would show up in other tests' goroutine
// checks.
func TestCallbackSignsInWhenTheEmailStepFails(t *testing.T) {
	for name, store := range map[string]func(*callbackFixture) *emailTestStore{
		"error": func(fixture *callbackFixture) *emailTestStore {
			return &emailTestStore{fixture: fixture, err: errors.New("private database detail")}
		},
		"stall": func(fixture *callbackFixture) *emailTestStore {
			return &emailTestStore{fixture: fixture, stall: true}
		},
		"unknown result": func(fixture *callbackFixture) *emailTestStore {
			return &emailTestStore{fixture: fixture}
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newCallbackFixture(t)
			fixture.providerEmail = "person@example.test"
			observer := &emailTestObserver{}
			withEmails(t, fixture, store(fixture), observer, nil, nil)
			fixture.service.emailTimeout = 50 * time.Millisecond
			result, err := fixture.service.CompleteBrowser(t.Context(), fixture.command)
			if err != nil || !result.Issued().IsValid() {
				t.Fatalf("a failed email step must not block sign-in: %v", err)
			}
			if !slices.Equal(observer.outcomes, []AccountEmailOutcome{AccountEmailOutcomeFailed}) {
				t.Fatalf("outcomes = %v", observer.outcomes)
			}
		})
	}
}

func TestCallbackSkipsAnEmailDevicesMayNotShow(t *testing.T) {
	t.Parallel()
	for _, email := range []string{"", "üser@example.test"} {
		fixture := newCallbackFixture(t)
		fixture.providerEmail = email
		store := &emailTestStore{fixture: fixture, result: AccountEmailRecorded}
		observer := &emailTestObserver{}
		withEmails(t, fixture, store, observer, nil, nil)
		if _, err := fixture.service.CompleteBrowser(t.Context(), fixture.command); err != nil || store.calls != 0 {
			t.Fatalf("email %q: calls=%d err=%v", email, store.calls, err)
		}
		if !slices.Equal(observer.outcomes, []AccountEmailOutcome{AccountEmailOutcomeSkipped}) {
			t.Fatalf("outcomes = %v", observer.outcomes)
		}
	}
}

func TestAccountEmailNeverPrints(t *testing.T) {
	t.Parallel()
	email := AccountEmail{Email: "person@example.test"}
	if email.String() != "[REDACTED]" || email.LogValue().String() != "[REDACTED]" {
		t.Fatal("an email request must never print")
	}
	for outcome, label := range map[AccountEmailOutcome]string{
		AccountEmailOutcomeSkipped: "skipped", AccountEmailOutcomeNoAccount: "no_account",
		AccountEmailOutcomeUnchanged: "unchanged", AccountEmailOutcomeRecorded: "recorded",
		AccountEmailOutcomeFailed: "failed", 0: "unknown",
	} {
		if outcome.String() != label {
			t.Errorf("%d.String() = %q, want %q", outcome, outcome.String(), label)
		}
	}
}

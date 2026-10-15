package oidcauth

import (
	"context"
	"errors"
	"slices"
	"testing"
)

type invitationTestAcceptor struct {
	fixture    *callbackFixture
	err        error
	acceptance InvitationAcceptance
}

func (acceptor *invitationTestAcceptor) AcceptInvitation(_ context.Context, acceptance InvitationAcceptance) error {
	acceptor.fixture.effects = append(acceptor.fixture.effects, "accept")
	acceptor.acceptance = acceptance
	return acceptor.err
}

func withInvitation(t *testing.T, fixture *callbackFixture, acceptor InvitationAcceptor) CallbackCommand {
	t.Helper()
	fixture.deps.Invitations = acceptor
	service, err := NewCallbackService(fixture.options, fixture.deps)
	if err != nil {
		t.Fatal(err)
	}
	fixture.service = service
	command, err := fixture.command.WithInvitation(NewInvitationProof([32]byte{7}))
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func TestCallbackAcceptsAnInvitationBeforeResolvingTheSubject(t *testing.T) {
	t.Parallel()
	fixture := newCallbackFixture(t)
	fixture.providerEmail = "Newcomer@Example.test"
	acceptor := &invitationTestAcceptor{fixture: fixture}
	command := withInvitation(t, fixture, acceptor)
	result, err := fixture.service.CompleteBrowser(t.Context(), command)
	if err != nil || !result.Issued().IsValid() {
		t.Fatalf("CompleteBrowser() = %v", err)
	}
	accept, resolve := slices.Index(fixture.effects, "accept"), slices.Index(fixture.effects, "resolve")
	exchange := slices.Index(fixture.effects, "exchange")
	if exchange < 0 || accept <= exchange || resolve <= accept {
		t.Fatalf("effects = %v, want exchange, accept, resolve", fixture.effects)
	}
	if !acceptor.acceptance.Lookup.IsValid() || acceptor.acceptance.Proof.Digest() != [32]byte{7} {
		t.Fatal("the acceptor must receive the sign-in lookup and the proof")
	}
	if acceptor.acceptance.Email != "Newcomer@Example.test" {
		t.Fatalf("acceptance email = %q, want the provider-verified address", acceptor.acceptance.Email)
	}
}

// An invitation names one address; a sign-in whose provider proved no address
// cannot show it is that person, so it never reaches the store.
func TestCallbackRefusesAnInvitationWithoutAVerifiedEmail(t *testing.T) {
	t.Parallel()
	fixture := newCallbackFixture(t)
	acceptor := &invitationTestAcceptor{fixture: fixture}
	command := withInvitation(t, fixture, acceptor)
	if _, err := fixture.service.CompleteBrowser(t.Context(), command); err == nil {
		t.Fatal("an invitation without a verified email must not issue a Session")
	}
	for _, effect := range []string{"accept", "resolve", "issue"} {
		if slices.Contains(fixture.effects, effect) {
			t.Fatalf("effects = %v, want no %s", fixture.effects, effect)
		}
	}
}

func TestCallbackFailsTheSignInWhenTheInvitationIsRefused(t *testing.T) {
	t.Parallel()
	for name, err := range map[string]error{
		"rejected":    ErrInvitationRejected,
		"unavailable": errors.New("private database detail"),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newCallbackFixture(t)
			command := withInvitation(t, fixture, &invitationTestAcceptor{fixture: fixture, err: err})
			if _, completeErr := fixture.service.CompleteBrowser(t.Context(), command); completeErr == nil {
				t.Fatal("a refused invitation must not issue a Session")
			}
			if slices.Contains(fixture.effects, "resolve") || slices.Contains(fixture.effects, "issue") {
				t.Fatalf("effects = %v, want no resolution or issuance", fixture.effects)
			}
		})
	}
	fixture := newCallbackFixture(t)
	command, err := fixture.command.WithInvitation(NewInvitationProof([32]byte{7}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.service.CompleteBrowser(t.Context(), command); err == nil {
		t.Fatal("a sign-in with an invitation but no acceptor must fail")
	}
}

func TestInvitationProofIsRedactedAndOptional(t *testing.T) {
	t.Parallel()
	fixture := newCallbackFixture(t)
	if _, err := fixture.command.WithInvitation(InvitationProof{}); err == nil {
		t.Fatal("an empty proof must be refused")
	}
	proof := NewInvitationProof([32]byte{1})
	if proof.String() != "[REDACTED]" || proof.LogValue().String() != "[REDACTED]" {
		t.Fatal("a proof must never print")
	}
}

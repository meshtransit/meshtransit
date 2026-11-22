package oidcauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

type refusalRecorder struct {
	mu       sync.Mutex
	refusals []InvitationRefusal
}

func (recorder *refusalRecorder) InvitationRefused(refusal InvitationRefusal) {
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	recorder.refusals = append(recorder.refusals, refusal)
}

// TD-SEC-37: a refused link is counted by its closed reason, and still
// answers as ErrInvitationRejected; an unavailable store is not a refusal.
func TestCallbackCountsRefusedInvitationsByReason(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		email string
		err   error
		want  []InvitationRefusal
	}{
		"another account":   {"someone@example.test", RefuseInvitation(InvitationRefusalEmailMismatch), []InvitationRefusal{InvitationRefusalEmailMismatch}},
		"used link":         {"someone@example.test", RefuseInvitation(InvitationRefusalNotPending), []InvitationRefusal{InvitationRefusalNotPending}},
		"bare rejection":    {"someone@example.test", ErrInvitationRejected, []InvitationRefusal{InvitationRefusalInvalid}},
		"no verified email": {"", nil, []InvitationRefusal{InvitationRefusalNoVerifiedEmail}},
		"store unavailable": {"someone@example.test", errors.New("private database detail"), nil},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newCallbackFixture(t)
			fixture.providerEmail = test.email
			recorder := &refusalRecorder{}
			fixture.deps.InvitationObserver = recorder
			command := withInvitation(t, fixture, &invitationTestAcceptor{fixture: fixture, err: test.err})
			if _, err := fixture.service.CompleteBrowser(t.Context(), command); err == nil {
				t.Fatal("a refused invitation must not issue a Session")
			}
			if len(recorder.refusals) != len(test.want) ||
				(len(test.want) == 1 && recorder.refusals[0] != test.want[0]) {
				t.Fatalf("refusals = %v, want %v", recorder.refusals, test.want)
			}
		})
	}
}

func TestInvitationRefusalLabelsAndMatching(t *testing.T) {
	t.Parallel()
	labels := map[InvitationRefusal]string{
		InvitationRefusalInvalid: "invalid", InvitationRefusalNoVerifiedEmail: "no_verified_email",
		InvitationRefusalEmailMismatch: "email_mismatch", InvitationRefusalNotPending: "not_pending",
		InvitationRefusalInviterAuthority: "inviter_authority", InvitationRefusalMemberConflict: "member_conflict",
		0: "unknown", 99: "unknown",
	}
	for refusal, want := range labels {
		if refusal.String() != want {
			t.Errorf("%d.String() = %q, want %q", refusal, refusal.String(), want)
		}
	}
	err := RefuseInvitation(InvitationRefusalEmailMismatch)
	if !errors.Is(err, ErrInvitationRejected) || invitationRefusal(err) != InvitationRefusalEmailMismatch ||
		invitationRefusal(errors.Join(errors.New("x"), err)) != InvitationRefusalEmailMismatch {
		t.Fatalf("refusal %v does not carry its reason", err)
	}
}

// The log line carries the reason only, at INFO for an ordinary mistake and
// WARN otherwise.
func TestCallbackLogsRefusedInvitationsWithTheReasonOnly(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		err   error
		level string
	}{
		"another account": {RefuseInvitation(InvitationRefusalEmailMismatch), "WARN"},
		"used link":       {RefuseInvitation(InvitationRefusalNotPending), "INFO"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newCallbackFixture(t)
			fixture.providerEmail = "someone@example.test"
			var buffer bytes.Buffer
			fixture.deps.Logger = slog.New(slog.NewJSONHandler(&buffer, nil))
			command := withInvitation(t, fixture, &invitationTestAcceptor{fixture: fixture, err: test.err})
			if _, err := fixture.service.CompleteBrowser(t.Context(), command); err == nil {
				t.Fatal("a refused invitation must not issue a Session")
			}
			var line map[string]any
			if err := json.Unmarshal(buffer.Bytes(), &line); err != nil {
				t.Fatalf("log %q: %v", buffer.String(), err)
			}
			if line["level"] != test.level || line["msg"] != "invitation link refused" || len(line) != 4 ||
				strings.Contains(buffer.String(), "someone") {
				t.Fatalf("log %v", line)
			}
		})
	}
}

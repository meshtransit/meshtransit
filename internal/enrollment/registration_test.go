package enrollment_test

import (
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestRegistrationLifecycle(t *testing.T) {
	t.Parallel()

	pending := mustRegistration(t, enrollment.RegistrationStatePending, node.ID{})
	authorized, err := pending.Authorize(testTime())
	if err != nil {
		t.Fatalf("Authorize() error = %v", err)
	}
	completed, err := authorized.Complete(mustNodeID(t), testTime())
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	nodeID, exists := completed.NodeID()
	if completed.State() != enrollment.RegistrationStateCompleted || !exists || nodeID != mustNodeID(t) {
		t.Fatal("registration did not reach the expected completed result")
	}
	if pending.State() != enrollment.RegistrationStatePending ||
		authorized.State() != enrollment.RegistrationStateAuthorized {
		t.Fatal("registration transition mutated a previous state")
	}
	if again, err := completed.Complete(nodeID, testTime()); err != nil || again.State() != completed.State() {
		t.Fatalf("repeated Complete() = (%v, %v), want idempotent completed", again.State(), err)
	}
	if again, err := authorized.Authorize(testTime()); err != nil || again.State() != authorized.State() {
		t.Fatalf("repeated Authorize() = (%v, %v), want idempotent authorized", again.State(), err)
	}
}

func TestRegistrationReject(t *testing.T) {
	t.Parallel()

	for _, state := range []enrollment.RegistrationState{
		enrollment.RegistrationStatePending,
		enrollment.RegistrationStateAuthorized,
	} {
		registration := mustRegistration(t, state, node.ID{})
		rejected, err := registration.Reject(testTime())
		if err != nil {
			t.Fatalf("Reject() error = %v", err)
		}
		if rejected.State() != enrollment.RegistrationStateRejected {
			t.Fatalf("Reject().State() = %v, want rejected", rejected.State())
		}
		again, err := rejected.Reject(testTime())
		if err != nil || again.State() != enrollment.RegistrationStateRejected {
			t.Fatalf("repeated Reject() = (%v, %v), want idempotent rejected", again.State(), err)
		}
	}
}

func TestRegistrationExpire(t *testing.T) {
	t.Parallel()

	pending := mustRegistration(t, enrollment.RegistrationStatePending, node.ID{})
	if _, err := pending.Expire(testTime()); !errors.Is(err, enrollment.ErrRegistrationTransition) {
		t.Fatalf("Expire() before deadline error = %v, want ErrRegistrationTransition", err)
	}
	expired, err := pending.Expire(testTime().Add(time.Hour))
	if err != nil {
		t.Fatalf("Expire() error = %v", err)
	}
	again, err := expired.Expire(testTime().Add(2 * time.Hour))
	if err != nil || again.State() != enrollment.RegistrationStateExpired {
		t.Fatalf("repeated Expire() = (%v, %v), want idempotent expired", again.State(), err)
	}
}

func TestRegistrationRejectsInvalidTransitions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		transition func(*testing.T, enrollment.Registration) error
	}{
		{
			name: "authorize completed",
			transition: func(_ *testing.T, registration enrollment.Registration) error {
				_, err := registration.Authorize(testTime())
				return err
			},
		},
		{
			name: "complete pending",
			transition: func(t *testing.T, registration enrollment.Registration) error {
				_, err := registration.Complete(mustNodeID(t), testTime())
				return err
			},
		},
		{
			name: "reject completed",
			transition: func(_ *testing.T, registration enrollment.Registration) error {
				_, err := registration.Reject(testTime())
				return err
			},
		},
	}

	completed := mustRegistration(t, enrollment.RegistrationStateCompleted, mustNodeID(t))
	pending := mustRegistration(t, enrollment.RegistrationStatePending, node.ID{})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			registration := completed
			if test.name == "complete pending" {
				registration = pending
			}
			if err := test.transition(t, registration); !errors.Is(err, enrollment.ErrRegistrationTransition) {
				t.Fatalf("transition error = %v, want ErrRegistrationTransition", err)
			}
		})
	}
}

func TestRegistrationDeadlineIsExclusive(t *testing.T) {
	t.Parallel()

	pending := mustRegistration(t, enrollment.RegistrationStatePending, node.ID{})
	if _, err := pending.Authorize(testTime().Add(time.Hour)); !errors.Is(err, enrollment.ErrRegistrationExpired) {
		t.Fatalf("Authorize() at deadline error = %v, want ErrRegistrationExpired", err)
	}
	authorized := mustRegistration(t, enrollment.RegistrationStateAuthorized, node.ID{})
	if _, err := authorized.Complete(mustNodeID(t), testTime().Add(time.Hour)); !errors.Is(err, enrollment.ErrRegistrationExpired) {
		t.Fatalf("Complete() at deadline error = %v, want ErrRegistrationExpired", err)
	}
}

func mustRegistration(
	t *testing.T,
	state enrollment.RegistrationState,
	nodeID node.ID,
) enrollment.Registration {
	t.Helper()

	registrationID, err := enrollment.ParseRegistrationID("01890f00-0000-7000-8000-000000000403")
	if err != nil {
		t.Fatalf("ParseRegistrationID() error = %v", err)
	}
	scope, err := network.NewScope(mustRegistrationWorkspaceID(t), mustRegistrationNetworkID(t))
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	fingerprint := [32]byte{}
	fingerprint[len(fingerprint)-1] = 1
	registration, err := enrollment.NewRegistration(enrollment.RegistrationParams{
		ID:                 registrationID,
		Scope:              scope,
		ProfileID:          mustProfileID(t),
		MachineFingerprint: fingerprint,
		State:              state,
		NodeID:             nodeID,
		CreatedAt:          testTime(),
		ExpiresAt:          testTime().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("NewRegistration() error = %v", err)
	}
	return registration
}

func mustRegistrationWorkspaceID(t *testing.T) workspace.ID {
	t.Helper()

	id, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	return id
}

func mustRegistrationNetworkID(t *testing.T) network.ID {
	t.Helper()

	id, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	return id
}

func mustNodeID(t *testing.T) node.ID {
	t.Helper()

	id, err := node.ParseID("01890f00-0000-7000-8000-000000000301")
	if err != nil {
		t.Fatalf("node.ParseID() error = %v", err)
	}
	return id
}

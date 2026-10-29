package meshgw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/k8sstate"
)

// A conflict on the state Secret stops the gateway; other write failures
// only fail the write.
func TestStopOnConflict(t *testing.T) {
	t.Parallel()
	ctx, fail := context.WithCancelCause(t.Context())
	failing := errors.New("API server unavailable")
	hook := stopOnConflict(func(context.Context, string, []byte) error { return failing }, fail)
	if err := hook(ctx, "a.json", nil); !errors.Is(err, failing) {
		t.Fatalf("hook error = %v", err)
	}
	if ctx.Err() != nil {
		t.Fatal("a plain failure stopped the gateway")
	}
	conflict := fmt.Errorf("%w: key x", k8sstate.ErrConflict)
	hook = stopOnConflict(func(context.Context, string, []byte) error { return conflict }, fail)
	if err := hook(ctx, "a.json", nil); !errors.Is(err, k8sstate.ErrConflict) {
		t.Fatalf("hook error = %v", err)
	}
	if !errors.Is(context.Cause(ctx), k8sstate.ErrConflict) {
		t.Fatalf("cause = %v, want the conflict", context.Cause(ctx))
	}
}

// Enrolling stops at once on what retrying cannot fix.
func TestEnrollUntilDoneStopsOnPermanentErrors(t *testing.T) {
	t.Parallel()
	approval := restored(daemon.RegistrationPending)
	err := enrollUntilDone(t.Context(), approval, enrollConfig(t, ""), time.Hour, slog.New(slog.DiscardHandler))
	if !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("enrollUntilDone() error = %v, want ErrApprovalRequired", err)
	}
}

// A failure that may pass is retried until it does.
func TestEnrollUntilDoneRetries(t *testing.T) {
	t.Parallel()
	unreachable := &fakeController{
		registration: daemon.RegistrationUnregistered, trustFailures: 2,
		trustErr: fmt.Errorf("%w: %w", daemon.ErrControlTrust, controlplane.ErrRegistrationTemporary),
	}
	err := enrollUntilDone(t.Context(), unreachable, enrollConfig(t, "mtk_key0"), time.Millisecond,
		slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("enrollUntilDone() error = %v", err)
	}
	if len(unreachable.trusted) != 3 || len(unreachable.logins) != 1 {
		t.Fatalf("trusted %d times, logins %v; want 3 and one login", len(unreachable.trusted), unreachable.logins)
	}
}

// A stop while enrolling returns the stop, without logging a retry.
func TestEnrollUntilDoneReturnsTheStop(t *testing.T) {
	t.Parallel()
	unreachable := &fakeController{
		registration: daemon.RegistrationUnregistered, trustFailures: -1,
		trustErr: fmt.Errorf("%w: %w", daemon.ErrControlTrust, controlplane.ErrRegistrationTemporary),
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	logs := newRecordingHandler()
	err := enrollUntilDone(ctx, unreachable, enrollConfig(t, "mtk_key0"), time.Hour, slog.New(logs))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("enrollUntilDone() error = %v, want the stop", err)
	}
	if _, logged := logs.find("enrolling failed; trying again"); logged {
		t.Fatal("a stop was logged as a failure to retry")
	}
}

type failingRunner struct{ err error }

func (r failingRunner) Run(context.Context) error { return r.err }

// A daemon that stops on its own stops the gateway, forwarder and all,
// instead of leaving it up and serving nothing.
func TestServeStopsWhenTheDaemonStops(t *testing.T) {
	t.Parallel()
	stacks := newTestStacks(t)
	_ = openTUN(t, stacks, gatewayConfig(gatewayAddr))
	forwarder := &KubeAPIForwarder{
		Stacks: stacks, Port: 443, Backend: "127.0.0.1:1", MaxConnections: 4, Logger: slog.New(slog.DiscardHandler),
	}
	stopped := errors.New("reading active profile for control sync")
	done := make(chan error, 1)
	go func() {
		done <- serve(t.Context(), failingRunner{err: stopped}, func(ctx context.Context) { _ = forwarder.Run(ctx) })
	}()
	select {
	case err := <-done:
		if !errors.Is(err, stopped) {
			t.Fatalf("serve() error = %v, want the daemon's", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve() did not return when the daemon stopped")
	}
}

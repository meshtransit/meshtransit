package dataplane

import (
	"context"
	"errors"
	"os"
	"testing"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
)

func TestEngineApplyLifecycle(t *testing.T) {
	t.Parallel()

	opener := &fakeTUNOpener{}
	engine, err := New(opener)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if state, err := engine.Apply(t.Context(), networkmap.Snapshot{}, NodePrivateKey{}); err != nil || state != StateIdle {
		t.Fatalf("empty Apply() = %q, %v", state, err)
	}
	if opener.calls != 0 {
		t.Fatalf("empty Apply() opened tun %d times", opener.calls)
	}

	authorized := networkmap.Snapshot{
		Peers:  []networkmap.Node{{ID: 2}},
		Policy: []networkmap.Rule{{Sources: []networkmap.Selector{{Kind: networkmap.SelectorAny}}}},
	}
	if state, err := engine.Apply(t.Context(), authorized, NodePrivateKey{}); err != nil || state != StateTUNReady {
		t.Fatalf("authorized Apply() = %q, %v", state, err)
	}
	if opener.calls != 1 {
		t.Fatalf("authorized Apply() opened tun %d times", opener.calls)
	}
	if state, err := engine.Apply(t.Context(), authorized, NodePrivateKey{}); err != nil || state != StateTUNReady {
		t.Fatalf("repeat Apply() = %q, %v", state, err)
	}
	if opener.calls != 1 {
		t.Fatalf("repeat Apply() opened tun %d times", opener.calls)
	}

	if state, err := engine.Apply(t.Context(), networkmap.Snapshot{}, NodePrivateKey{}); err != nil || state != StateIdle {
		t.Fatalf("deny Apply() = %q, %v", state, err)
	}
	if _, err := opener.lastFile.Stat(); err == nil {
		t.Fatal("deny Apply() left tun descriptor open")
	}
}

func TestEngineApplyRejectsInvalidHelperResult(t *testing.T) {
	t.Parallel()

	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	opener := &fakeTUNOpener{result: netadmin.TUN{File: file}}
	engine, err := New(opener)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	state, err := engine.Apply(t.Context(), networkmap.Snapshot{
		Peers:  []networkmap.Node{{ID: 2}},
		Policy: []networkmap.Rule{{Sources: []networkmap.Selector{{Kind: networkmap.SelectorAny}}}},
	}, NodePrivateKey{})
	if state != StateFailed || err == nil {
		t.Fatalf("Apply() = %q, %v, want failed", state, err)
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("invalid helper descriptor was not closed")
	}
}

func TestEngineApplyHonorsCancellation(t *testing.T) {
	t.Parallel()

	engine, err := New(&fakeTUNOpener{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := engine.Apply(ctx, networkmap.Snapshot{}, NodePrivateKey{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply() error = %v, want context cancellation", err)
	}
}

type fakeTUNOpener struct {
	calls    int
	result   netadmin.TUN
	lastFile *os.File
}

func (f *fakeTUNOpener) OpenTUN(
	_ context.Context,
	_ netadmin.TUNConfig,
) (netadmin.TUN, error) {
	f.calls++
	if f.result.File != nil {
		f.lastFile = f.result.File

		return f.result, nil
	}
	file, err := os.Open(os.DevNull)
	if err != nil {
		return netadmin.TUN{}, err
	}
	f.lastFile = file

	return netadmin.TUN{File: file, Name: "mesh0", MTU: 1280}, nil
}

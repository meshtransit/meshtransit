package dnsconfig

import (
	"context"
	"errors"
	"slices"
	"testing"

	"meshtransit.net/client/internal/networkmap"
)

func TestManagerApplyAndDisableOrdering(t *testing.T) {
	t.Parallel()

	calls := []string{}
	resolver := &fakeResolver{calls: &calls}
	host := &fakeHost{calls: &calls}
	manager, err := NewManager(resolver, host)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	configured, err := manager.Apply(t.Context(), dnsSnapshot())
	if err != nil {
		t.Fatalf("enabled Apply() error = %v", err)
	}
	if !configured {
		t.Fatal("enabled Apply() configured = false")
	}
	if got, want := calls, []string{"resolver:on", "host:on"}; !slices.Equal(got, want) {
		t.Fatalf("enabled calls = %v, want %v", got, want)
	}

	calls = nil
	configured, err = manager.Apply(t.Context(), networkmap.Snapshot{Revision: 8})
	if err != nil {
		t.Fatalf("disabled Apply() error = %v", err)
	}
	if configured {
		t.Fatal("disabled Apply() configured = true")
	}
	if got, want := calls, []string{"host:off", "resolver:off"}; !slices.Equal(got, want) {
		t.Fatalf("disabled calls = %v, want %v", got, want)
	}
}

func TestManagerRollsBackResolverAfterHostFailure(t *testing.T) {
	t.Parallel()

	calls := []string{}
	resolver := &fakeResolver{calls: &calls}
	host := &fakeHost{calls: &calls}
	manager, err := NewManager(resolver, host)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if _, err := manager.Apply(t.Context(), dnsSnapshot()); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	calls = nil
	host.err = errors.New("host failed")
	updated := dnsSnapshot()
	updated.Revision++
	if _, err := manager.Apply(t.Context(), updated); err == nil {
		t.Fatal("failed Apply() error = nil")
	}
	if got, want := calls, []string{"resolver:on", "host:on", "resolver:on"}; !slices.Equal(got, want) {
		t.Fatalf("rollback calls = %v, want %v", got, want)
	}
	if resolver.plans[len(resolver.plans)-1].Revision != 7 {
		t.Fatalf("resolver rollback revision = %d, want 7", resolver.plans[len(resolver.plans)-1].Revision)
	}
}

func TestManagerDisableRollsBackHostAfterResolverFailure(t *testing.T) {
	t.Parallel()

	calls := []string{}
	resolver := &fakeResolver{calls: &calls}
	host := &fakeHost{calls: &calls}
	manager, err := NewManager(resolver, host)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if _, err := manager.Apply(t.Context(), dnsSnapshot()); err != nil {
		t.Fatalf("initial Apply() error = %v", err)
	}

	calls = nil
	resolver.errWhenDisabled = errors.New("resolver failed")
	if _, err := manager.Apply(t.Context(), networkmap.Snapshot{Revision: 8}); err == nil {
		t.Fatal("disabled Apply() error = nil")
	}
	if got, want := calls, []string{"host:off", "resolver:off", "host:on"}; !slices.Equal(got, want) {
		t.Fatalf("rollback calls = %v, want %v", got, want)
	}
}

func TestManagerCloseIsOrderedAndIdempotent(t *testing.T) {
	t.Parallel()

	calls := []string{}
	resolver := &fakeResolver{calls: &calls}
	host := &fakeHost{calls: &calls}
	manager, err := NewManager(resolver, host)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if _, err := manager.Apply(t.Context(), dnsSnapshot()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	calls = nil
	if err := manager.Close(t.Context()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := manager.Close(t.Context()); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if got, want := calls, []string{"host:off", "resolver:off"}; !slices.Equal(got, want) {
		t.Fatalf("close calls = %v, want %v", got, want)
	}
	if _, err := manager.Apply(t.Context(), dnsSnapshot()); !errors.Is(err, ErrClosed) {
		t.Fatalf("Apply() after close error = %v, want ErrClosed", err)
	}
}

func TestManagerResetKeepsManagerReusable(t *testing.T) {
	t.Parallel()

	calls := []string{}
	resolver := &fakeResolver{calls: &calls}
	host := &fakeHost{calls: &calls}
	manager, err := NewManager(resolver, host)
	if err != nil {
		t.Fatalf("NewManager() error = %v", err)
	}
	if _, err := manager.Apply(t.Context(), dnsSnapshot()); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	calls = nil
	if err := manager.Reset(t.Context()); err != nil {
		t.Fatalf("Reset() error = %v", err)
	}
	if configured, err := manager.Apply(t.Context(), dnsSnapshot()); err != nil {
		t.Fatalf("Apply() after reset error = %v", err)
	} else if !configured {
		t.Fatal("Apply() after reset configured = false")
	}
	if got, want := calls, []string{"host:off", "resolver:off", "resolver:on", "host:on"}; !slices.Equal(got, want) {
		t.Fatalf("reset/reapply calls = %v, want %v", got, want)
	}
}

type fakeResolver struct {
	calls           *[]string
	plans           []Plan
	errWhenDisabled error
}

func (f *fakeResolver) Apply(_ context.Context, plan Plan) error {
	state := "off"
	if plan.Enabled {
		state = "on"
	}
	*f.calls = append(*f.calls, "resolver:"+state)
	f.plans = append(f.plans, clonePlan(plan))
	if !plan.Enabled {
		return f.errWhenDisabled
	}

	return nil
}

func (f *fakeResolver) Close(context.Context) error { return nil }

type fakeHost struct {
	calls *[]string
	err   error
}

func (f *fakeHost) Apply(_ context.Context, plan Plan) error {
	state := "off"
	if plan.Enabled {
		state = "on"
	}
	*f.calls = append(*f.calls, "host:"+state)
	if plan.Enabled {
		return f.err
	}

	return nil
}

// Root turning DNS off keeps the host's own DNS and reports it; on again
// applies the map; the choice is ignored while an exit node is in use
// (DNS design D5b).
func TestManagerKeepsTheHostsDNSWhenTurnedOff(t *testing.T) {
	t.Parallel()
	calls := []string{}
	manager, err := NewManager(&fakeResolver{calls: &calls}, &fakeHost{calls: &calls})
	if err != nil {
		t.Fatal(err)
	}
	reapplied := make(chan error, 2)
	manager.OnReapply(func(_ networkmap.Snapshot, err error) { reapplied <- err })
	manager.SetUse(false) // no map yet: nothing to apply
	configured, err := manager.Apply(t.Context(), dnsSnapshot())
	if err != nil || configured || manager.UsesMeshDNS() {
		t.Fatalf("off: configured %v, uses %v, %v", configured, manager.UsesMeshDNS(), err)
	}
	if got, want := calls, []string{"host:off", "resolver:on"}; !slices.Equal(got, want) {
		t.Fatalf("off calls = %v, want %v", got, want)
	}
	calls = calls[:0]
	manager.SetUse(true)
	if err := <-reapplied; err != nil || !manager.UsesMeshDNS() {
		t.Fatalf("on again: %v, uses %v", err, manager.UsesMeshDNS())
	}
	if got, want := calls, []string{"resolver:on", "host:on"}; !slices.Equal(got, want) {
		t.Fatalf("on calls = %v, want %v", got, want)
	}
	manager.SetUse(true) // no change: nothing applied
	select {
	case err := <-reapplied:
		t.Fatalf("an unchanged choice applied the map again: %v", err)
	default:
	}
}

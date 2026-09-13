package app

import (
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestRuntimeStateValidatesAndCopiesRoles(t *testing.T) {
	t.Parallel()

	roles := []Role{RoleAPI, RoleWorker}
	state, err := NewRuntimeState(roles)
	if err != nil {
		t.Fatalf("NewRuntimeState() error = %v", err)
	}
	roles[0] = RoleRelay

	got := state.Roles()
	if !reflect.DeepEqual(got, []string{"api", "worker"}) {
		t.Fatalf("Roles() = %v, want [api worker]", got)
	}
	got[0] = "control"
	if !reflect.DeepEqual(state.Roles(), []string{"api", "worker"}) {
		t.Fatalf("Roles() returned mutable internal state: %v", state.Roles())
	}
}

func TestRuntimeStateRejectsInvalidRoles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		roles []Role
	}{
		{name: "missing", roles: nil},
		{name: "unknown", roles: []Role{RoleUnknown}},
		{name: "aggregate", roles: []Role{RoleAll}},
		{name: "duplicate", roles: []Role{RoleAPI, RoleAPI}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			state, err := NewRuntimeState(test.roles)
			if !errors.Is(err, ErrInvalidRuntimeState) {
				t.Fatalf("NewRuntimeState() error = %v, want ErrInvalidRuntimeState", err)
			}
			if state != nil {
				t.Fatalf("NewRuntimeState() = %v, want nil", state)
			}
		})
	}
}

func TestRuntimeStateAdmissionGate(t *testing.T) {
	t.Parallel()

	state, err := NewRuntimeState([]Role{RoleControl})
	if err != nil {
		t.Fatalf("NewRuntimeState() error = %v", err)
	}
	if state.Ready() {
		t.Fatal("Ready() = true before admission opens")
	}
	state.SetReady(true)
	if state.Ready() {
		t.Fatal("Ready() = true while required dependencies are unknown")
	}
	if err := state.SetComponentStatus(ComponentPostgreSQL, ComponentStatusReady); err != nil {
		t.Fatalf("SetComponentStatus(postgresql) error = %v", err)
	}
	if err := state.SetComponentStatus(ComponentRedis, ComponentStatusReady); err != nil {
		t.Fatalf("SetComponentStatus(redis) error = %v", err)
	}
	if !state.Ready() {
		t.Fatal("Ready() = false after admission and dependencies are ready")
	}
}

func TestRuntimeStateTracksDependencyLossAndRecovery(t *testing.T) {
	t.Parallel()

	state, err := NewRuntimeState([]Role{RoleWorker})
	if err != nil {
		t.Fatalf("NewRuntimeState() error = %v", err)
	}
	state.SetReady(true)
	if err := state.SetComponentStatuses(map[Component]ComponentStatus{
		ComponentPostgreSQL: ComponentStatusReady,
		ComponentRedis:      ComponentStatusUnavailable,
	}); err != nil {
		t.Fatalf("SetComponentStatuses() error = %v", err)
	}
	if state.Ready() {
		t.Fatal("Ready() = true while redis is unavailable")
	}

	snapshot := state.Snapshot()
	if got := snapshot.Components["postgresql"]; got != "ready" {
		t.Fatalf("postgresql status = %q, want ready", got)
	}
	if got := snapshot.Components["redis"]; got != "unavailable" {
		t.Fatalf("redis status = %q, want unavailable", got)
	}

	if err := state.SetComponentStatus(ComponentRedis, ComponentStatusReady); err != nil {
		t.Fatalf("SetComponentStatus(redis) error = %v", err)
	}
	if !state.Ready() {
		t.Fatal("Ready() = false after redis recovered")
	}
	if snapshot.Ready {
		t.Fatal("Snapshot() mutated after later state update")
	}
}

func TestRuntimeStateRejectsInvalidComponentUpdates(t *testing.T) {
	t.Parallel()

	state, err := NewRuntimeState([]Role{RoleRelay})
	if err != nil {
		t.Fatalf("NewRuntimeState() error = %v", err)
	}
	tests := []struct {
		component Component
		status    ComponentStatus
	}{
		{component: ComponentPostgreSQL, status: ComponentStatusReady},
		{component: ComponentUnknown, status: ComponentStatusReady},
		{component: ComponentRedis, status: ComponentStatusUnknown},
		{component: ComponentRedis, status: ComponentStatus(255)},
	}
	for _, test := range tests {
		if err := state.SetComponentStatus(test.component, test.status); !errors.Is(err, ErrInvalidRuntimeState) {
			t.Fatalf("SetComponentStatus(%v, %v) error = %v, want ErrInvalidRuntimeState", test.component, test.status, err)
		}
	}
}

func TestRelayReadinessHasNoStorageRequirement(t *testing.T) {
	t.Parallel()

	state, err := NewRuntimeState([]Role{RoleRelay})
	if err != nil {
		t.Fatalf("NewRuntimeState() error = %v", err)
	}
	state.SetReady(true)
	if !state.Ready() {
		t.Fatal("Ready() = false for admitted relay role")
	}
	if got := state.Snapshot().Components; len(got) != 0 {
		t.Fatalf("relay components = %v, want empty", got)
	}
}

func TestRuntimeStateSupportsConcurrentReadersAndWriters(t *testing.T) {
	t.Parallel()

	state, err := NewRuntimeState([]Role{RoleAPI, RoleWorker})
	if err != nil {
		t.Fatalf("NewRuntimeState() error = %v", err)
	}

	start := make(chan struct{})
	var workers sync.WaitGroup
	for writer := range 4 {
		workers.Go(func() {
			<-start
			for iteration := range 500 {
				status := ComponentStatusReady
				if (writer+iteration)%2 == 0 {
					status = ComponentStatusUnavailable
				}
				if err := state.SetComponentStatuses(map[Component]ComponentStatus{
					ComponentPostgreSQL: status,
					ComponentRedis:      status,
				}); err != nil {
					t.Errorf("SetComponentStatuses() error = %v", err)
					return
				}
				state.SetReady(iteration%2 == 0)
			}
		})
	}
	for range 4 {
		workers.Go(func() {
			<-start
			for range 500 {
				snapshot := state.Snapshot()
				if snapshot.Ready && (snapshot.Components["postgresql"] != "ready" ||
					snapshot.Components["redis"] != "ready") {
					t.Errorf("ready snapshot has unavailable component: %+v", snapshot)
					return
				}
				_ = state.Ready()
			}
		})
	}
	close(start)
	workers.Wait()
}

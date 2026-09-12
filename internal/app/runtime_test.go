package app

import (
	"errors"
	"reflect"
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
	if !state.Ready() {
		t.Fatal("Ready() = false after admission opens")
	}
}

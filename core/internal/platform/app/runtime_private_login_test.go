package app

import (
	"errors"
	"testing"
)

func TestPrivateLoginReadinessIsIsolatedAndAPIScoped(t *testing.T) {
	t.Parallel()
	for _, roles := range [][]Role{
		{RoleAPI},
		{RoleAPI, RoleControl, RoleWorker, RoleRelay, RoleIdentity},
	} {
		state, err := NewRuntimeState(roles, ComponentPrivateLogin)
		if err != nil {
			t.Fatal(err)
		}
		state.SetReady(true)
		for _, component := range []Component{ComponentPostgreSQL, ComponentRedis} {
			if err := state.SetComponentStatus(component, ComponentStatusReady); err != nil {
				t.Fatal(err)
			}
		}
		for _, component := range []Component{
			ComponentIdentityPostgreSQL, ComponentIdentityConfiguration, ComponentIdentitySigner,
		} {
			if _, required := state.statuses[component]; required {
				if err := state.SetComponentStatus(component, ComponentStatusReady); err != nil {
					t.Fatal(err)
				}
			}
		}
		snapshot := state.Snapshot()
		if !state.Ready() || !snapshot.LoginConfigured || snapshot.LoginReady ||
			snapshot.Components["private_login"] != "unknown" {
			t.Fatal("private login incorrectly gated Core or admitted login")
		}
		if err := state.SetComponentStatus(ComponentPrivateLogin, ComponentStatusReady); err != nil ||
			!state.Ready() || !state.Snapshot().LoginReady {
			t.Fatal("complete login prerequisite did not admit login")
		}
		err = state.SetComponentStatus(ComponentPrivateLogin, ComponentStatusUnavailable)
		if err != nil || !state.Ready() || state.Snapshot().LoginReady {
			t.Fatal("provider outage changed Core readiness or admitted login")
		}
	}
	for _, test := range []struct {
		roles      []Role
		components []Component
	}{
		{roles: []Role{RoleControl}, components: []Component{ComponentPrivateLogin}},
		{roles: []Role{RoleWorker}, components: []Component{ComponentPrivateLogin}},
		{roles: []Role{RoleRelay}, components: []Component{ComponentPrivateLogin}},
		{roles: []Role{RoleAPI}, components: []Component{ComponentPostgreSQL}},
		{roles: []Role{RoleAPI}, components: []Component{ComponentPrivateLogin, ComponentPrivateLogin}},
	} {
		if state, err := NewRuntimeState(test.roles, test.components...); state != nil || !errors.Is(err, ErrInvalidRuntimeState) {
			t.Fatal("unsupported readiness component")
		}
	}
}

func TestAllRoleIdentityFailureDoesNotEvictCore(t *testing.T) {
	t.Parallel()

	state, err := NewRuntimeState([]Role{RoleAPI, RoleControl, RoleWorker, RoleRelay, RoleIdentity})
	if err != nil {
		t.Fatal(err)
	}
	state.SetReady(true)
	if err := state.SetComponentStatuses(map[Component]ComponentStatus{
		ComponentPostgreSQL:            ComponentStatusReady,
		ComponentRedis:                 ComponentStatusReady,
		ComponentIdentityPostgreSQL:    ComponentStatusUnavailable,
		ComponentIdentityConfiguration: ComponentStatusUnavailable,
		ComponentIdentitySigner:        ComponentStatusUnavailable,
	}); err != nil {
		t.Fatal(err)
	}
	if !state.Ready() {
		t.Fatal("identity outage evicted healthy Core")
	}
	if state.AdmissionRequired(ComponentIdentityPostgreSQL) ||
		state.AdmissionRequired(ComponentIdentityConfiguration) ||
		state.AdmissionRequired(ComponentIdentitySigner) {
		t.Fatal("co-located identity component gates Core admission")
	}
}

func TestIdentityOnlyReadinessFailsClosed(t *testing.T) {
	t.Parallel()

	state, err := NewRuntimeState([]Role{RoleIdentity})
	if err != nil {
		t.Fatal(err)
	}
	state.SetReady(true)
	if err := state.SetComponentStatuses(map[Component]ComponentStatus{
		ComponentIdentityPostgreSQL:    ComponentStatusReady,
		ComponentIdentityConfiguration: ComponentStatusUnavailable,
		ComponentIdentitySigner:        ComponentStatusReady,
	}); err != nil {
		t.Fatal(err)
	}
	if state.Ready() || !state.AdmissionRequired(ComponentIdentityConfiguration) {
		t.Fatal("identity-only process bypassed broker readiness")
	}
}

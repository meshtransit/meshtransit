package app

import (
	"errors"
	"testing"
)

func TestPrivateLoginReadinessIsOptionalAndAPIScoped(t *testing.T) {
	t.Parallel()
	for _, roles := range [][]Role{{RoleAPI}, {RoleAPI, RoleControl, RoleWorker, RoleRelay}} {
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
		if state.Ready() || state.Snapshot().Components["private_login"] != "unknown" {
			t.Fatal("listener admission bypassed prerequisite")
		}
		if err := state.SetComponentStatus(ComponentPrivateLogin, ComponentStatusReady); err != nil || !state.Ready() {
			t.Fatal("complete prerequisite did not admit")
		}
		err = state.SetComponentStatus(ComponentPrivateLogin, ComponentStatusUnavailable)
		if err != nil || state.Ready() {
			t.Fatal("provider outage admitted")
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

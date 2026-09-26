package app

import (
	"errors"
	"reflect"
	"testing"
)

func TestRequiredComponentsUsesRoleUnion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		roles []Role
		want  []Component
	}{
		{name: "api", roles: []Role{RoleAPI}, want: []Component{ComponentPostgreSQL, ComponentRedis}},
		{name: "control", roles: []Role{RoleControl}, want: []Component{ComponentPostgreSQL, ComponentRedis}},
		{name: "worker", roles: []Role{RoleWorker}, want: []Component{ComponentPostgreSQL, ComponentRedis}},
		{name: "relay", roles: []Role{RoleRelay}, want: nil},
		{
			name: "identity", roles: []Role{RoleIdentity},
			want: []Component{ComponentIdentityPostgreSQL, ComponentIdentityConfiguration},
		},
		{
			name:  "deduplicated union",
			roles: []Role{RoleAPI, RoleControl, RoleWorker, RoleRelay, RoleIdentity},
			want: []Component{
				ComponentPostgreSQL, ComponentRedis,
				ComponentIdentityPostgreSQL, ComponentIdentityConfiguration,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := RequiredComponents(test.roles)
			if err != nil {
				t.Fatalf("RequiredComponents() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("RequiredComponents() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRequiredComponentsRejectsInvalidRoles(t *testing.T) {
	t.Parallel()

	tests := [][]Role{
		nil,
		{RoleUnknown},
		{RoleAll},
		{RoleAPI, RoleAPI},
	}
	for _, roles := range tests {
		if _, err := RequiredComponents(roles); !errors.Is(err, ErrInvalidApplication) {
			t.Fatalf("RequiredComponents(%v) error = %v, want ErrInvalidApplication", roles, err)
		}
	}
}

func TestComponentStringIsStableAndSafe(t *testing.T) {
	t.Parallel()

	tests := map[Component]string{
		ComponentUnknown:               "unknown",
		ComponentPostgreSQL:            "postgresql",
		ComponentRedis:                 "redis",
		ComponentPrivateLogin:          "private_login",
		ComponentIdentityPostgreSQL:    "identity_postgresql",
		ComponentIdentityConfiguration: "identity_configuration",
		Component(255):                 "unknown",
	}
	for component, want := range tests {
		if got := component.String(); got != want {
			t.Fatalf("Component(%d).String() = %q, want %q", component, got, want)
		}
	}
}

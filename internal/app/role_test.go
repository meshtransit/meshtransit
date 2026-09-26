package app

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  Role
	}{
		{name: "all", value: "all", want: RoleAll},
		{name: "api", value: "api", want: RoleAPI},
		{name: "control", value: "control", want: RoleControl},
		{name: "worker", value: "worker", want: RoleWorker},
		{name: "relay", value: "relay", want: RoleRelay},
		{name: "identity", value: "identity", want: RoleIdentity},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseRole(test.value)
			if err != nil {
				t.Fatalf("ParseRole() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("ParseRole() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestParseRoleRejectsNonCanonicalValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{name: "empty", value: ""},
		{name: "uppercase", value: "API"},
		{name: "multiple", value: "api,worker"},
		{name: "whitespace", value: " api"},
		{name: "unknown", value: "scheduler"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseRole(test.value)
			if !errors.Is(err, ErrInvalidRole) {
				t.Fatalf("ParseRole() error = %v, want ErrInvalidRole", err)
			}
			if got != RoleUnknown {
				t.Fatalf("ParseRole() = %v, want RoleUnknown", got)
			}
		})
	}
}

func TestExpandRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		role Role
		want []Role
	}{
		{
			name: "all responsibilities",
			role: RoleAll,
			want: []Role{RoleAPI, RoleControl, RoleWorker, RoleRelay},
		},
		{name: "api only", role: RoleAPI, want: []Role{RoleAPI}},
		{name: "control only", role: RoleControl, want: []Role{RoleControl}},
		{name: "worker only", role: RoleWorker, want: []Role{RoleWorker}},
		{name: "relay only", role: RoleRelay, want: []Role{RoleRelay}},
		{name: "identity only", role: RoleIdentity, want: []Role{RoleIdentity}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := ExpandRole(test.role)
			if err != nil {
				t.Fatalf("ExpandRole() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ExpandRole() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestExpandRoleRejectsUnknown(t *testing.T) {
	t.Parallel()

	got, err := ExpandRole(RoleUnknown)
	if !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("ExpandRole() error = %v, want ErrInvalidRole", err)
	}
	if got != nil {
		t.Fatalf("ExpandRole() = %v, want nil", got)
	}
}

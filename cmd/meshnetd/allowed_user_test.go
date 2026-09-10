package main

import (
	"errors"
	"os/user"
	"testing"
)

func TestResolveAllowedUID(t *testing.T) {
	t.Parallel()

	lookup := func(name string) (*user.User, error) {
		if name == "empty" {
			return nil, nil
		}
		if name == "invalid" {
			return &user.User{Username: name, Uid: "not-a-uid"}, nil
		}
		if name != "meshd" {
			return nil, errors.New("unknown user")
		}

		return &user.User{Username: name, Uid: "1234"}, nil
	}
	tests := []struct {
		name      string
		hasUID    bool
		uid       uint64
		username  string
		want      uint32
		wantError bool
	}{
		{name: "numeric uid", hasUID: true, uid: 42, want: 42},
		{name: "numeric uid overflow", hasUID: true, uid: 1 << 32, wantError: true},
		{name: "service account", username: "meshd", want: 1234},
		{name: "missing selector", wantError: true},
		{name: "both selectors", hasUID: true, uid: 42, username: "meshd", wantError: true},
		{name: "unsafe account name", username: "../meshd", wantError: true},
		{name: "empty account", username: "empty", wantError: true},
		{name: "invalid account uid", username: "invalid", wantError: true},
		{name: "unknown account", username: "missing", wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := resolveAllowedUID(
				test.hasUID,
				test.uid,
				test.username,
				lookup,
			)
			if (err != nil) != test.wantError {
				t.Fatalf("resolveAllowedUID() error = %v, wantError %t", err, test.wantError)
			}
			if got != test.want {
				t.Fatalf("resolveAllowedUID() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestValidUserName(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"meshd", "_meshd", "mesh-daemon", "mesh_daemon2"} {
		if !validUserName(value) {
			t.Errorf("validUserName(%q) = false", value)
		}
	}
	for _, value := range []string{"", "Meshd", "2meshd", "mesh.daemon", "mesh/daemon"} {
		if validUserName(value) {
			t.Errorf("validUserName(%q) = true", value)
		}
	}
}

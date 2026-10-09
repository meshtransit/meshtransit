package main

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/platform/app"
)

func TestRunRejectsInvalidConfigurationBeforeListening(t *testing.T) {
	t.Parallel()

	lookup := func(key string) (string, bool) {
		if key == "MESHTRANSIT_ROLE" {
			return "unknown", true
		}
		return "", false
	}
	var errorOutput bytes.Buffer

	exitCode := run(context.Background(), lookup, &errorOutput)
	if exitCode != 1 {
		t.Fatalf("run() = %d, want 1", exitCode)
	}
	if !strings.Contains(errorOutput.String(), `"msg":"startup failed"`) {
		t.Fatalf("error output = %q, want structured startup failure", errorOutput.String())
	}
	if strings.Contains(errorOutput.String(), "unknown") {
		t.Fatalf("error output exposed invalid configuration value: %s", errorOutput.String())
	}
}

func TestRunRelayDoesNotRequireStorage(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lookup := func(key string) (string, bool) {
		if key == "MESHTRANSIT_ROLE" {
			return "relay", true
		}
		return "", false
	}
	var errorOutput bytes.Buffer

	if exitCode := run(ctx, lookup, &errorOutput); exitCode != 0 {
		t.Fatalf("run() = %d, want 0; output = %s", exitCode, errorOutput.String())
	}
}

func TestUnavailableDependenciesReportsOnlyClosedComponents(t *testing.T) {
	t.Parallel()

	state, err := app.NewRuntimeState([]app.Role{app.RoleAPI}, app.ComponentPrivateLogin)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.SetComponentStatuses(map[app.Component]app.ComponentStatus{
		app.ComponentPostgreSQL:   app.ComponentStatusReady,
		app.ComponentRedis:        app.ComponentStatusReady,
		app.ComponentPrivateLogin: app.ComponentStatusUnavailable,
	}); err != nil {
		t.Fatal(err)
	}

	if got := unavailableDependencies(state); !slices.Equal(got, []string{"private_login"}) {
		t.Fatalf("unavailableDependencies() = %v, want private_login", got)
	}
}

func TestRuntimeFailurePhaseUsesClosedClassifications(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		err  error
		want string
	}{
		{err: errors.Join(errors.New("private detail"), errPrivateIdentityAdmissionCheck), want: "private_login_admission"},
		{err: errors.Join(errors.New("private detail"), errPrivateIdentityDiscoveryDeadline), want: "private_login_discovery_deadline"},
		{err: errors.Join(errors.New("private detail"), errPrivateIdentityDiscoveryMetadata), want: "private_login_discovery_metadata"},
		{err: errors.Join(errors.New("private detail"), errPrivateIdentityDiscoveryTransport), want: "private_login_discovery_transport"},
		{err: errors.Join(errors.New("private detail"), errPrivateIdentityDiscoveryCheck), want: "private_login_discovery"},
		{err: errors.New("private detail"), want: "unclassified"},
	} {
		if got := runtimeFailurePhase(test.err); got != test.want {
			t.Fatalf("runtimeFailurePhase() = %q, want %q", got, test.want)
		}
	}
}

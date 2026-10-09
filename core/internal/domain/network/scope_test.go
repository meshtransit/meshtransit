package network_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/workspace"
)

func TestNewScope(t *testing.T) {
	t.Parallel()

	workspaceID := mustWorkspaceID(t)
	networkID := mustNetworkID(t)
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("NewScope() error = %v", err)
	}
	if scope.WorkspaceID() != workspaceID || scope.NetworkID() != networkID || !scope.IsValid() {
		t.Fatal("NewScope() did not preserve its exact Workspace and Network")
	}
}

func TestNewScopeRejectsIncompleteScope(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		workspaceID workspace.ID
		networkID   network.ID
	}{
		{name: "missing workspace", networkID: mustNetworkID(t)},
		{name: "missing network", workspaceID: mustWorkspaceID(t)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := network.NewScope(test.workspaceID, test.networkID)
			if !errors.Is(err, network.ErrInvalidScope) {
				t.Fatalf("NewScope() error = %v, want ErrInvalidScope", err)
			}
		})
	}
	if (network.Scope{}).IsValid() {
		t.Fatal("zero Scope is valid")
	}
}

func mustWorkspaceID(t *testing.T) workspace.ID {
	t.Helper()

	id, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	return id
}

func mustNetworkID(t *testing.T) network.ID {
	t.Helper()

	id, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	return id
}

package authorization_test

import (
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/core/internal/domain/authorization"
)

func TestPublicIDConstructors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		value     [16]byte
		construct func([16]byte) error
		wantErr   bool
	}{
		{
			name:  "deployment id",
			value: testUUIDv7(1),
			construct: func(value [16]byte) error {
				_, err := authorization.NewDeploymentID(value)
				return err
			},
		},
		{
			name:  "workspace id",
			value: testUUIDv7(2),
			construct: func(value [16]byte) error {
				_, err := authorization.NewWorkspaceID(value)
				return err
			},
		},
		{
			name:  "network id",
			value: testUUIDv7(3),
			construct: func(value [16]byte) error {
				_, err := authorization.NewNetworkID(value)
				return err
			},
		},
		{
			name:  "principal id",
			value: testUUIDv7(4),
			construct: func(value [16]byte) error {
				_, err := authorization.NewPrincipalID(value)
				return err
			},
		},
		{
			name:      "zero id",
			value:     [16]byte{},
			construct: deploymentIDError,
			wantErr:   true,
		},
		{
			name:      "wrong uuid version",
			value:     testUUIDVersion(4, 5),
			construct: deploymentIDError,
			wantErr:   true,
		},
		{
			name:      "wrong uuid variant",
			value:     testUUIDVariant(0xc0, 6),
			construct: deploymentIDError,
			wantErr:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.construct(test.value)
			if test.wantErr {
				if !errors.Is(err, authorization.ErrInvalidPublicID) {
					t.Fatalf("constructor error = %v, want ErrInvalidPublicID", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("constructor error = %v", err)
			}
		})
	}
}

func TestScopeConstructors(t *testing.T) {
	t.Parallel()

	deployment := mustDeploymentID(t, 1)
	workspace := mustWorkspaceID(t, 2)
	network := mustNetworkID(t, 3)

	tests := []struct {
		name      string
		construct func() (authorization.Scope, error)
		wantKind  authorization.ScopeKind
		wantErr   bool
	}{
		{
			name: "deployment",
			construct: func() (authorization.Scope, error) {
				return authorization.NewDeploymentScope(deployment)
			},
			wantKind: authorization.ScopeDeployment,
		},
		{
			name: "workspace",
			construct: func() (authorization.Scope, error) {
				return authorization.NewWorkspaceScope(deployment, workspace)
			},
			wantKind: authorization.ScopeWorkspace,
		},
		{
			name: "network",
			construct: func() (authorization.Scope, error) {
				return authorization.NewNetworkScope(deployment, workspace, network)
			},
			wantKind: authorization.ScopeNetwork,
		},
		{
			name: "invalid workspace id",
			construct: func() (authorization.Scope, error) {
				return authorization.NewWorkspaceScope(deployment, authorization.WorkspaceID{})
			},
			wantErr: true,
		},
		{
			name: "invalid network id",
			construct: func() (authorization.Scope, error) {
				return authorization.NewNetworkScope(deployment, workspace, authorization.NetworkID{})
			},
			wantErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			scope, err := test.construct()
			if test.wantErr {
				if !errors.Is(err, authorization.ErrInvalidScope) {
					t.Fatalf("scope constructor error = %v, want ErrInvalidScope", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("scope constructor error = %v", err)
			}
			if scope.Kind() != test.wantKind {
				t.Fatalf("Scope.Kind() = %v, want %v", scope.Kind(), test.wantKind)
			}
		})
	}
}

func deploymentIDError(value [16]byte) error {
	_, err := authorization.NewDeploymentID(value)
	return err
}

func testUUIDv7(seed byte) [16]byte {
	return testUUIDVariant(0x80, seed)
}

func testUUIDVersion(version byte, seed byte) [16]byte {
	value := testUUIDv7(seed)
	value[6] = version << 4
	return value
}

func testUUIDVariant(variant byte, seed byte) [16]byte {
	value := [16]byte{0x01, 0x89, 0x0f}
	value[6] = 0x70
	value[8] = variant
	value[15] = seed
	return value
}

func mustDeploymentID(t *testing.T, seed byte) authorization.DeploymentID {
	t.Helper()

	id, err := authorization.NewDeploymentID(testUUIDv7(seed))
	if err != nil {
		t.Fatalf("NewDeploymentID() error = %v", err)
	}
	return id
}

func mustWorkspaceID(t *testing.T, seed byte) authorization.WorkspaceID {
	t.Helper()

	id, err := authorization.NewWorkspaceID(testUUIDv7(seed))
	if err != nil {
		t.Fatalf("NewWorkspaceID() error = %v", err)
	}
	return id
}

func mustNetworkID(t *testing.T, seed byte) authorization.NetworkID {
	t.Helper()

	id, err := authorization.NewNetworkID(testUUIDv7(seed))
	if err != nil {
		t.Fatalf("NewNetworkID() error = %v", err)
	}
	return id
}

func mustPrincipalID(t *testing.T, seed byte) authorization.PrincipalID {
	t.Helper()

	id, err := authorization.NewPrincipalID(testUUIDv7(seed))
	if err != nil {
		t.Fatalf("NewPrincipalID() error = %v", err)
	}
	return id
}

func mustDeploymentScope(t *testing.T, deployment authorization.DeploymentID) authorization.Scope {
	t.Helper()

	scope, err := authorization.NewDeploymentScope(deployment)
	if err != nil {
		t.Fatalf("NewDeploymentScope() error = %v", err)
	}
	return scope
}

func mustWorkspaceScope(
	t *testing.T,
	deployment authorization.DeploymentID,
	workspace authorization.WorkspaceID,
) authorization.Scope {
	t.Helper()

	scope, err := authorization.NewWorkspaceScope(deployment, workspace)
	if err != nil {
		t.Fatalf("NewWorkspaceScope() error = %v", err)
	}
	return scope
}

func mustNetworkScope(
	t *testing.T,
	deployment authorization.DeploymentID,
	workspace authorization.WorkspaceID,
	network authorization.NetworkID,
) authorization.Scope {
	t.Helper()

	scope, err := authorization.NewNetworkScope(deployment, workspace, network)
	if err != nil {
		t.Fatalf("NewNetworkScope() error = %v", err)
	}
	return scope
}

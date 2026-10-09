package authorization_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/authorization"
)

func TestNewGrant(t *testing.T) {
	t.Parallel()

	principal := mustPrincipalID(t, 1)
	deployment := mustDeploymentID(t, 2)
	workspace := mustWorkspaceID(t, 3)
	network := mustNetworkID(t, 4)
	workspaceScope := mustWorkspaceScope(t, deployment, workspace)
	networkScope := mustNetworkScope(t, deployment, workspace, network)

	tests := []struct {
		name    string
		options authorization.GrantOptions
		wantErr error
	}{
		{
			name: "active exact grant",
			options: authorization.GrantOptions{
				PrincipalID:         principal,
				Permission:          authorization.PermissionNetworkUpdate,
				Scope:               networkScope,
				AuthorityGeneration: 7,
				State:               authorization.GrantActive,
			},
		},
		{
			name: "implicit parent grant",
			options: authorization.GrantOptions{
				PrincipalID:         principal,
				Permission:          authorization.PermissionNetworkUpdate,
				Scope:               workspaceScope,
				AuthorityGeneration: 7,
				State:               authorization.GrantActive,
			},
			wantErr: authorization.ErrInvalidScope,
		},
		{
			name: "zero principal",
			options: authorization.GrantOptions{
				Permission:          authorization.PermissionNetworkUpdate,
				Scope:               networkScope,
				AuthorityGeneration: 7,
				State:               authorization.GrantActive,
			},
			wantErr: authorization.ErrInvalidPublicID,
		},
		{
			name: "unknown permission",
			options: authorization.GrantOptions{
				PrincipalID:         principal,
				Permission:          "network.*",
				Scope:               networkScope,
				AuthorityGeneration: 7,
				State:               authorization.GrantActive,
			},
			wantErr: authorization.ErrUnknownPermission,
		},
		{
			name: "invalid binding scope for permission",
			options: authorization.GrantOptions{
				PrincipalID:         principal,
				Permission:          authorization.PermissionWorkspaceUpdate,
				Scope:               networkScope,
				AuthorityGeneration: 7,
				State:               authorization.GrantActive,
			},
			wantErr: authorization.ErrInvalidScope,
		},
		{
			name: "zero generation",
			options: authorization.GrantOptions{
				PrincipalID: principal,
				Permission:  authorization.PermissionNetworkUpdate,
				Scope:       networkScope,
				State:       authorization.GrantActive,
			},
			wantErr: authorization.ErrInvalidAuthorityGeneration,
		},
		{
			name: "unknown state",
			options: authorization.GrantOptions{
				PrincipalID:         principal,
				Permission:          authorization.PermissionNetworkUpdate,
				Scope:               networkScope,
				AuthorityGeneration: 7,
			},
			wantErr: authorization.ErrInvalidGrantState,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := authorization.NewGrant(test.options)
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("NewGrant() error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("NewGrant() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

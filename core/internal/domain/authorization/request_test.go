package authorization_test

import (
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/authorization"
)

func TestNewRequest(t *testing.T) {
	t.Parallel()

	principal := mustPrincipalID(t, 1)
	deployment := mustDeploymentID(t, 2)
	workspace := mustWorkspaceID(t, 3)
	network := mustNetworkID(t, 4)
	workspaceScope := mustWorkspaceScope(t, deployment, workspace)
	networkScope := mustNetworkScope(t, deployment, workspace, network)
	now := time.Date(2026, time.September, 13, 5, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		options authorization.RequestOptions
		wantErr error
	}{
		{
			name: "network request",
			options: authorization.RequestOptions{
				PrincipalID:         principal,
				Permission:          authorization.PermissionNetworkUpdate,
				Target:              networkScope,
				AuthorityGeneration: 1,
				EvaluatedAt:         now,
			},
		},
		{
			name: "network create targets workspace",
			options: authorization.RequestOptions{
				PrincipalID:         principal,
				Permission:          authorization.PermissionNetworkCreate,
				Target:              workspaceScope,
				AuthorityGeneration: 1,
				EvaluatedAt:         now,
			},
		},
		{
			name: "zero principal",
			options: authorization.RequestOptions{
				Permission:          authorization.PermissionNetworkUpdate,
				Target:              networkScope,
				AuthorityGeneration: 1,
				EvaluatedAt:         now,
			},
			wantErr: authorization.ErrInvalidPublicID,
		},
		{
			name: "unknown permission",
			options: authorization.RequestOptions{
				PrincipalID:         principal,
				Permission:          "network.*",
				Target:              networkScope,
				AuthorityGeneration: 1,
				EvaluatedAt:         now,
			},
			wantErr: authorization.ErrUnknownPermission,
		},
		{
			name: "permission cannot target scope",
			options: authorization.RequestOptions{
				PrincipalID:         principal,
				Permission:          authorization.PermissionWorkspaceUpdate,
				Target:              networkScope,
				AuthorityGeneration: 1,
				EvaluatedAt:         now,
			},
			wantErr: authorization.ErrInvalidScope,
		},
		{
			name: "zero generation",
			options: authorization.RequestOptions{
				PrincipalID: principal,
				Permission:  authorization.PermissionNetworkUpdate,
				Target:      networkScope,
				EvaluatedAt: now,
			},
			wantErr: authorization.ErrInvalidAuthorityGeneration,
		},
		{
			name: "zero evaluation time",
			options: authorization.RequestOptions{
				PrincipalID:         principal,
				Permission:          authorization.PermissionNetworkUpdate,
				Target:              networkScope,
				AuthorityGeneration: 1,
			},
			wantErr: authorization.ErrInvalidEvaluationTime,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := authorization.NewRequest(test.options)
			if test.wantErr == nil {
				if err != nil {
					t.Fatalf("NewRequest() error = %v", err)
				}
				return
			}
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("NewRequest() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

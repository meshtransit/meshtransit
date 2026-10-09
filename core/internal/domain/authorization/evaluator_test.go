package authorization_test

import (
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/authorization"
)

func TestEvaluate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 13, 5, 0, 0, 0, time.UTC)
	deployment := mustDeploymentID(t, 1)
	workspaceOne := mustWorkspaceID(t, 11)
	workspaceTwo := mustWorkspaceID(t, 12)
	networkOne := mustNetworkID(t, 21)
	networkTwo := mustNetworkID(t, 22)
	principal := mustPrincipalID(t, 31)
	otherPrincipal := mustPrincipalID(t, 32)
	networkOneScope := mustNetworkScope(t, deployment, workspaceOne, networkOne)
	networkTwoScope := mustNetworkScope(t, deployment, workspaceTwo, networkTwo)
	request := mustRequest(t, authorization.RequestOptions{
		PrincipalID:         principal,
		Permission:          authorization.PermissionNetworkUpdate,
		Target:              networkOneScope,
		AuthorityGeneration: 7,
		EvaluatedAt:         now,
	})
	validGrant := mustGrant(t, authorization.GrantOptions{
		PrincipalID:         principal,
		Permission:          authorization.PermissionNetworkUpdate,
		Scope:               networkOneScope,
		AuthorityGeneration: 7,
		State:               authorization.GrantActive,
	})

	tests := []struct {
		name       string
		request    authorization.Request
		grants     []authorization.Grant
		wantAllow  bool
		wantReason authorization.Reason
	}{
		{
			name:       "exact active grant",
			request:    request,
			grants:     []authorization.Grant{validGrant},
			wantAllow:  true,
			wantReason: authorization.ReasonAllowed,
		},
		{
			name:       "no grants",
			request:    request,
			wantReason: authorization.ReasonNoMatchingGrant,
		},
		{
			name:    "different principal",
			request: request,
			grants: []authorization.Grant{mustGrant(t, authorization.GrantOptions{
				PrincipalID:         otherPrincipal,
				Permission:          authorization.PermissionNetworkUpdate,
				Scope:               networkOneScope,
				AuthorityGeneration: 7,
				State:               authorization.GrantActive,
			})},
			wantReason: authorization.ReasonNoMatchingGrant,
		},
		{
			name:    "different permission",
			request: request,
			grants: []authorization.Grant{mustGrant(t, authorization.GrantOptions{
				PrincipalID:         principal,
				Permission:          authorization.PermissionNetworkRead,
				Scope:               networkOneScope,
				AuthorityGeneration: 7,
				State:               authorization.GrantActive,
			})},
			wantReason: authorization.ReasonNoMatchingGrant,
		},
		{
			name:    "cross workspace scope",
			request: request,
			grants: []authorization.Grant{mustGrant(t, authorization.GrantOptions{
				PrincipalID:         principal,
				Permission:          authorization.PermissionNetworkUpdate,
				Scope:               networkTwoScope,
				AuthorityGeneration: 7,
				State:               authorization.GrantActive,
			})},
			wantReason: authorization.ReasonNoMatchingGrant,
		},
		{
			name:    "revoked grant",
			request: request,
			grants: []authorization.Grant{mustGrant(t, authorization.GrantOptions{
				PrincipalID:         principal,
				Permission:          authorization.PermissionNetworkUpdate,
				Scope:               networkOneScope,
				AuthorityGeneration: 7,
				State:               authorization.GrantRevoked,
			})},
			wantReason: authorization.ReasonInactiveGrant,
		},
		{
			name:    "expired at boundary",
			request: request,
			grants: []authorization.Grant{mustGrant(t, authorization.GrantOptions{
				PrincipalID:         principal,
				Permission:          authorization.PermissionNetworkUpdate,
				Scope:               networkOneScope,
				AuthorityGeneration: 7,
				State:               authorization.GrantActive,
				ExpiresAt:           now,
			})},
			wantReason: authorization.ReasonExpiredGrant,
		},
		{
			name:    "stale authority generation",
			request: request,
			grants: []authorization.Grant{mustGrant(t, authorization.GrantOptions{
				PrincipalID:         principal,
				Permission:          authorization.PermissionNetworkUpdate,
				Scope:               networkOneScope,
				AuthorityGeneration: 6,
				State:               authorization.GrantActive,
			})},
			wantReason: authorization.ReasonStaleGeneration,
		},
		{
			name:    "valid grant wins after stale grant",
			request: request,
			grants: []authorization.Grant{
				mustGrant(t, authorization.GrantOptions{
					PrincipalID:         principal,
					Permission:          authorization.PermissionNetworkUpdate,
					Scope:               networkOneScope,
					AuthorityGeneration: 6,
					State:               authorization.GrantActive,
				}),
				validGrant,
			},
			wantAllow:  true,
			wantReason: authorization.ReasonAllowed,
		},
		{
			name:       "zero request",
			wantReason: authorization.ReasonInvalidRequest,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			decision := authorization.Evaluate(test.request, test.grants)
			if decision.IsAllowed() != test.wantAllow || decision.Reason() != test.wantReason {
				t.Fatalf(
					"Evaluate() = (allowed %t, reason %q), want (allowed %t, reason %q)",
					decision.IsAllowed(),
					decision.Reason(),
					test.wantAllow,
					test.wantReason,
				)
			}
		})
	}
}

func TestEvaluateRejectsOversizedGrantSet(t *testing.T) {
	t.Parallel()

	deployment := mustDeploymentID(t, 1)
	workspace := mustWorkspaceID(t, 2)
	network := mustNetworkID(t, 3)
	principal := mustPrincipalID(t, 4)
	networkScope := mustNetworkScope(t, deployment, workspace, network)
	request := mustRequest(t, authorization.RequestOptions{
		PrincipalID:         principal,
		Permission:          authorization.PermissionNetworkUpdate,
		Target:              networkScope,
		AuthorityGeneration: 1,
		EvaluatedAt:         time.Date(2026, time.September, 13, 5, 0, 0, 0, time.UTC),
	})
	grant := mustGrant(t, authorization.GrantOptions{
		PrincipalID:         principal,
		Permission:          authorization.PermissionNetworkUpdate,
		Scope:               networkScope,
		AuthorityGeneration: 1,
		State:               authorization.GrantActive,
	})
	grants := make([]authorization.Grant, authorization.MaxEvaluatedGrants+1)
	for index := range grants {
		grants[index] = grant
	}

	decision := authorization.Evaluate(request, grants)
	if decision.IsAllowed() || decision.Reason() != authorization.ReasonGrantSetTooLarge {
		t.Fatalf("Evaluate() = (allowed %t, reason %q), want bounded denial", decision.IsAllowed(), decision.Reason())
	}
}

func TestEvaluateDenialReasonIsOrderIndependent(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.September, 13, 5, 0, 0, 0, time.UTC)
	deployment := mustDeploymentID(t, 1)
	workspace := mustWorkspaceID(t, 2)
	network := mustNetworkID(t, 3)
	principal := mustPrincipalID(t, 4)
	networkScope := mustNetworkScope(t, deployment, workspace, network)
	request := mustRequest(t, authorization.RequestOptions{
		PrincipalID:         principal,
		Permission:          authorization.PermissionNetworkUpdate,
		Target:              networkScope,
		AuthorityGeneration: 2,
		EvaluatedAt:         now,
	})
	expired := mustGrant(t, authorization.GrantOptions{
		PrincipalID:         principal,
		Permission:          authorization.PermissionNetworkUpdate,
		Scope:               networkScope,
		AuthorityGeneration: 2,
		State:               authorization.GrantActive,
		ExpiresAt:           now,
	})
	stale := mustGrant(t, authorization.GrantOptions{
		PrincipalID:         principal,
		Permission:          authorization.PermissionNetworkUpdate,
		Scope:               networkScope,
		AuthorityGeneration: 1,
		State:               authorization.GrantActive,
	})

	for _, grants := range [][]authorization.Grant{{expired, stale}, {stale, expired}} {
		decision := authorization.Evaluate(request, grants)
		if decision.IsAllowed() || decision.Reason() != authorization.ReasonStaleGeneration {
			t.Fatalf(
				"Evaluate() = (allowed %t, reason %q), want stable stale-generation denial",
				decision.IsAllowed(),
				decision.Reason(),
			)
		}
	}
}

func mustGrant(t *testing.T, options authorization.GrantOptions) authorization.Grant {
	t.Helper()

	grant, err := authorization.NewGrant(options)
	if err != nil {
		t.Fatalf("NewGrant() error = %v", err)
	}
	return grant
}

func mustRequest(t *testing.T, options authorization.RequestOptions) authorization.Request {
	t.Helper()

	request, err := authorization.NewRequest(options)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	return request
}

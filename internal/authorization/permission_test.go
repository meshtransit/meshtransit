package authorization_test

import (
	"regexp"
	"testing"

	"github.com/meshtransit/meshtransit/internal/authorization"
)

func TestPermissions(t *testing.T) {
	t.Parallel()

	permissions := authorization.Permissions()
	if len(permissions) != 77 {
		t.Fatalf("len(Permissions()) = %d, want 77", len(permissions))
	}
	permissionPattern := regexp.MustCompile(`^[a-z][a-z0-9_]*\.[a-z][a-z0-9_.]*$`)
	seen := make(map[authorization.Permission]struct{}, len(permissions))
	for _, permission := range permissions {
		if !permissionPattern.MatchString(string(permission)) {
			t.Errorf("permission %q is not a stable lowercase resource.action identifier", permission)
		}
		if _, exists := seen[permission]; exists {
			t.Errorf("permission %q appears more than once", permission)
		}
		seen[permission] = struct{}{}
		definition, ok := authorization.LookupPermission(permission)
		if !ok || definition.Permission() != permission {
			t.Errorf("LookupPermission(%q) = (%q, %t)", permission, definition.Permission(), ok)
		}
	}

	permissions[0] = authorization.Permission("changed.permission")
	if authorization.Permissions()[0] == permissions[0] {
		t.Fatal("Permissions() returned mutable shared catalog storage")
	}
	if _, ok := authorization.LookupPermission("network.*"); ok {
		t.Fatal("wildcard permission was accepted")
	}
}

func TestPermissionDefinitionAppliesToScope(t *testing.T) {
	t.Parallel()

	deployment := mustDeploymentID(t, 1)
	workspaceOne := mustWorkspaceID(t, 11)
	workspaceTwo := mustWorkspaceID(t, 12)
	networkOne := mustNetworkID(t, 21)
	networkTwo := mustNetworkID(t, 22)
	deploymentScope := mustDeploymentScope(t, deployment)
	workspaceOneScope := mustWorkspaceScope(t, deployment, workspaceOne)
	workspaceTwoScope := mustWorkspaceScope(t, deployment, workspaceTwo)
	networkOneScope := mustNetworkScope(t, deployment, workspaceOne, networkOne)
	networkTwoScope := mustNetworkScope(t, deployment, workspaceTwo, networkTwo)

	tests := []struct {
		name       string
		permission authorization.Permission
		binding    authorization.Scope
		target     authorization.Scope
		want       bool
	}{
		{
			name:       "deployment permission exact deployment",
			permission: authorization.PermissionDeploymentRead,
			binding:    deploymentScope,
			target:     deploymentScope,
			want:       true,
		},
		{
			name:       "deployment permission does not descend",
			permission: authorization.PermissionDeploymentRead,
			binding:    deploymentScope,
			target:     workspaceOneScope,
		},
		{
			name:       "workspace permission exact workspace",
			permission: authorization.PermissionWorkspaceUpdate,
			binding:    workspaceOneScope,
			target:     workspaceOneScope,
			want:       true,
		},
		{
			name:       "workspace permission does not descend",
			permission: authorization.PermissionWorkspaceUpdate,
			binding:    workspaceOneScope,
			target:     networkOneScope,
		},
		{
			name:       "network permission does not implicitly descend",
			permission: authorization.PermissionNetworkUpdate,
			binding:    workspaceOneScope,
			target:     networkOneScope,
		},
		{
			name:       "network permission exact network",
			permission: authorization.PermissionNetworkUpdate,
			binding:    networkOneScope,
			target:     networkOneScope,
			want:       true,
		},
		{
			name:       "network permission rejects cross workspace",
			permission: authorization.PermissionNetworkUpdate,
			binding:    workspaceOneScope,
			target:     networkTwoScope,
		},
		{
			name:       "network permission rejects sibling network",
			permission: authorization.PermissionNetworkUpdate,
			binding:    networkOneScope,
			target:     mustNetworkScope(t, deployment, workspaceOne, networkTwo),
		},
		{
			name:       "network create targets workspace",
			permission: authorization.PermissionNetworkCreate,
			binding:    workspaceOneScope,
			target:     workspaceOneScope,
			want:       true,
		},
		{
			name:       "network create cannot target a network",
			permission: authorization.PermissionNetworkCreate,
			binding:    workspaceOneScope,
			target:     networkOneScope,
		},
		{
			name:       "isolation does not implicitly descend",
			permission: authorization.PermissionIsolationQuarantine,
			binding:    workspaceOneScope,
			target:     networkOneScope,
		},
		{
			name:       "isolation cannot cross workspace",
			permission: authorization.PermissionIsolationQuarantine,
			binding:    workspaceOneScope,
			target:     workspaceTwoScope,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			definition, ok := authorization.LookupPermission(test.permission)
			if !ok {
				t.Fatalf("LookupPermission(%q) did not find catalog entry", test.permission)
			}
			if got := definition.Applies(test.binding, test.target); got != test.want {
				t.Fatalf("Definition.Applies() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestEveryPermissionHasAnApplicableScopeRelation(t *testing.T) {
	t.Parallel()

	deployment := mustDeploymentID(t, 1)
	workspace := mustWorkspaceID(t, 2)
	network := mustNetworkID(t, 3)
	scopes := []authorization.Scope{
		mustDeploymentScope(t, deployment),
		mustWorkspaceScope(t, deployment, workspace),
		mustNetworkScope(t, deployment, workspace, network),
	}

	for _, permission := range authorization.Permissions() {
		definition, ok := authorization.LookupPermission(permission)
		if !ok {
			t.Fatalf("LookupPermission(%q) did not find catalog entry", permission)
		}
		hasApplicableRelation := false
		for _, binding := range scopes {
			for _, target := range scopes {
				if definition.Applies(binding, target) {
					hasApplicableRelation = true
				}
			}
		}
		if !hasApplicableRelation {
			t.Errorf("permission %q has no applicable scope relation", permission)
		}
	}
}

func TestSharingPermissionsRequireExactNetworkScope(t *testing.T) {
	t.Parallel()

	deployment := mustDeploymentID(t, 71)
	workspace := mustWorkspaceID(t, 72)
	otherWorkspace := mustWorkspaceID(t, 73)
	network := mustNetworkID(t, 74)
	otherNetwork := mustNetworkID(t, 75)
	exact := mustNetworkScope(t, deployment, workspace, network)
	workspaceScope := mustWorkspaceScope(t, deployment, workspace)
	sibling := mustNetworkScope(t, deployment, workspace, otherNetwork)
	crossWorkspace := mustNetworkScope(t, deployment, otherWorkspace, network)

	permissions := []authorization.Permission{
		authorization.PermissionShareRead,
		authorization.PermissionShareOffer,
		authorization.PermissionShareAccept,
		authorization.PermissionShareRevoke,
	}
	for _, permission := range permissions {
		permission := permission
		t.Run(string(permission), func(t *testing.T) {
			t.Parallel()

			definition, ok := authorization.LookupPermission(permission)
			if !ok {
				t.Fatalf("LookupPermission(%q) did not find sharing permission", permission)
			}
			if !definition.Applies(exact, exact) {
				t.Fatal("sharing permission rejected its exact Network scope")
			}
			for name, target := range map[string]authorization.Scope{
				"Workspace":       workspaceScope,
				"sibling Network": sibling,
				"cross Workspace": crossWorkspace,
			} {
				if definition.Applies(exact, target) {
					t.Errorf("sharing permission widened to %s target", name)
				}
				if definition.Applies(workspaceScope, exact) {
					t.Errorf("sharing permission inherited from Workspace binding for %s case", name)
				}
			}
		})
	}
}

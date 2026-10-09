package authorization

import (
	"slices"
	"testing"
)

func TestBuiltinRolesGrantOnlyCatalogPermissions(t *testing.T) {
	t.Parallel()
	for _, role := range BuiltinRoles() {
		permissions := role.Permissions()
		if len(permissions) == 0 {
			t.Fatalf("%s grants nothing", role)
		}
		seen := map[Permission]bool{}
		for _, permission := range permissions {
			if _, known := LookupPermission(permission); !known {
				t.Fatalf("%s grants unknown permission %q", role, permission)
			}
			if seen[permission] {
				t.Fatalf("%s lists %q twice", role, permission)
			}
			seen[permission] = true
		}
	}
}

func TestBuiltinRolesNeverGrantOwnerOrPlatformPermissions(t *testing.T) {
	t.Parallel()
	forbidden := []Permission{
		PermissionWorkspaceDelete, PermissionWorkspaceOwnerTransfer, PermissionRoleDefinitionManage,
		PermissionDeploymentRead, PermissionDeploymentSecurityManage, PermissionDeploymentRoleBind,
		PermissionDeploymentOperate, PermissionSupportGrantUse, "support.grant.manage",
	}
	for _, role := range BuiltinRoles() {
		for _, permission := range forbidden {
			if role.Grants(permission) {
				t.Fatalf("%s grants owner or platform permission %q", role, permission)
			}
		}
	}
}

func TestBuiltinRoleBoundaries(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		role       BuiltinRole
		granted    []Permission
		notGranted []Permission
	}{
		{
			role:       BuiltinRoleNetworkAdmin,
			granted:    []Permission{"policy.publish", "share.offer", "dns.manage", "route.approve"},
			notGranted: []Permission{"device.manage", "member.invite", "role_binding.manage", "billing.manage"},
		},
		{
			role:       BuiltinRoleITAdmin,
			granted:    []Permission{"device.manage", "member.invite", "role_binding.manage", "session.revoke"},
			notGranted: []Permission{"policy.publish", "share.offer", "dns.manage", "billing.manage"},
		},
		{
			role:       BuiltinRoleBillingAdmin,
			granted:    []Permission{"billing.manage"},
			notGranted: []Permission{"device.read", "policy.read", "member.read"},
		},
		{
			role:       BuiltinRoleAuditor,
			granted:    []Permission{"audit.export", "policy.read", "member.read"},
			notGranted: []Permission{"policy.publish", "device.manage", "billing.manage", "audit.read.secret"},
		},
	} {
		for _, permission := range test.granted {
			if !test.role.Grants(permission) {
				t.Errorf("%s lost %q", test.role, permission)
			}
		}
		for _, permission := range test.notGranted {
			if test.role.Grants(permission) {
				t.Errorf("%s widened to %q", test.role, permission)
			}
		}
	}
}

func TestBuiltinRoleDelegationCeiling(t *testing.T) {
	t.Parallel()
	if BuiltinRoleAdmin.AssignableBy(RoleAssignerITAdmin) {
		t.Fatal("it_admin can grant admin")
	}
	if !BuiltinRoleAdmin.AssignableBy(RoleAssignerOwner) || !BuiltinRoleAdmin.AssignableBy(RoleAssignerAdmin) {
		t.Fatal("owner and admin must grant admin")
	}
	for _, role := range []BuiltinRole{BuiltinRoleNetworkAdmin, BuiltinRoleITAdmin, BuiltinRoleBillingAdmin, BuiltinRoleAuditor} {
		if !role.AssignableBy(RoleAssignerITAdmin) {
			t.Fatalf("it_admin cannot grant %s", role)
		}
	}
	scoped := []BuiltinRole{}
	for _, role := range BuiltinRoles() {
		if role.NetworkScopeAllowed() {
			scoped = append(scoped, role)
		}
	}
	if !slices.Equal(scoped, []BuiltinRole{BuiltinRoleNetworkAdmin, BuiltinRoleITAdmin, BuiltinRoleAuditor}) {
		t.Fatalf("Network-scoped roles = %v", scoped)
	}
	if _, err := ParseBuiltinRole("owner"); err == nil {
		t.Fatal("owner must not be assignable")
	}
	if _, err := ParseBuiltinRole("member"); err == nil {
		t.Fatal("member must not be assignable")
	}
}

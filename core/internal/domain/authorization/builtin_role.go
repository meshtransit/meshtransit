package authorization

import (
	"errors"
	"slices"
)

// ErrUnknownBuiltinRole reports a role key outside the built-in catalog.
var ErrUnknownBuiltinRole = errors.New("authorization: unknown built-in role")

// BuiltinRole is one assignable built-in Workspace role (ADR-050 D6). Owner is
// Workspace ownership and member is implicit membership, so neither appears
// here. The database seeds the same catalog in schema 95; an integration test
// keeps both identical.
type BuiltinRole string

const (
	// BuiltinRoleAdmin administers everything except ownership and deletion.
	BuiltinRoleAdmin BuiltinRole = "admin"
	// BuiltinRoleNetworkAdmin owns policy, DNS, routes, Resources and sharing.
	BuiltinRoleNetworkAdmin BuiltinRole = "network_admin"
	// BuiltinRoleITAdmin owns members, identity, roles and Devices.
	BuiltinRoleITAdmin BuiltinRole = "it_admin"
	// BuiltinRoleBillingAdmin owns billing only.
	BuiltinRoleBillingAdmin BuiltinRole = "billing_admin"
	// BuiltinRoleAuditor reads everything and exports audit.
	BuiltinRoleAuditor BuiltinRole = "auditor"
	// BuiltinRoleSecurityAdmin sets guardrails and reads everything else,
	// separating who sets the limits from who operates Networks.
	BuiltinRoleSecurityAdmin BuiltinRole = "security_admin"
)

// RoleAssigner names who may assign a role: Workspace ownership or a
// Workspace-scope built-in role.
type RoleAssigner string

const (
	// RoleAssignerOwner is the Workspace owner.
	RoleAssignerOwner RoleAssigner = "owner"
	// RoleAssignerAdmin is a Workspace-scope admin.
	RoleAssignerAdmin RoleAssigner = "admin"
	// RoleAssignerITAdmin is a Workspace-scope it_admin.
	RoleAssignerITAdmin RoleAssigner = "it_admin"
)

type builtinRoleDefinition struct {
	networkScopeAllowed bool
	assignableBy        []RoleAssigner
	permissions         []Permission
}

var builtinRoleCatalog = map[BuiltinRole]builtinRoleDefinition{
	BuiltinRoleAdmin: {
		assignableBy: []RoleAssigner{RoleAssignerOwner, RoleAssignerAdmin},
		permissions: permissionsOf(
			"workspace.read", "workspace.update", "network.create",
			"member.read", "member.invite", "member.manage",
			"identity_provider.manage", "identity_group.manage", "identity_group.read",
			"device_tag.read", "device_tag.manage", "interchange.read", "interchange.manage",
			"role_definition.read", "role_binding.read", "role_binding.manage",
			"approval_policy.manage", "access_review.manage", "support.grant.read",
			"billing.read", "billing.manage",
			"isolation.read", "isolation.quarantine", "isolation.restore",
			"guardrail.read", "guardrail.manage", "guardrail.weaken",
			"audit.read", "audit.export",
			"network.read", "network.update", "network.suspend", "network.delete", "dns.manage",
			"network.member.manage",
			"device.read", "device.manage", "device.transfer", "device.quarantine", "session.revoke",
			"enrollment_profile.read", "enrollment_profile.manage",
			"enrollment_credential.issue", "enrollment_credential.revoke",
			"device_group.read", "device_group.manage", "device_group.members.manage",
			"device_group.delegation.manage",
			"policy.read", "policy.draft", "policy.validate", "policy.approve", "policy.publish",
			"policy.rollback", "policy.explain",
			"route.read", "route.approve", "route.withdraw", "connector.read", "connector.manage",
			"resource.read", "resource.manage", "resource.export", "resource.transfer",
			"resource_group.read", "resource_group.manage", "resource_group.transfer",
			"share.read", "share.offer", "share.accept", "share.revoke",
		),
	},
	BuiltinRoleNetworkAdmin: {
		networkScopeAllowed: true,
		assignableBy:        []RoleAssigner{RoleAssignerOwner, RoleAssignerAdmin, RoleAssignerITAdmin},
		permissions: permissionsOf(
			"workspace.read", "network.create", "member.read", "role_binding.read",
			"identity_group.read", "device_tag.read", "interchange.read",
			"isolation.read", "guardrail.read", "audit.read",
			"network.read", "network.update", "dns.manage",
			"device.read", "device_group.read", "device_group.manage", "device_group.members.manage",
			"enrollment_profile.read",
			"policy.read", "policy.draft", "policy.validate", "policy.approve", "policy.publish",
			"policy.rollback", "policy.explain",
			"route.read", "route.approve", "route.withdraw", "connector.read", "connector.manage",
			"resource.read", "resource.manage", "resource.export",
			"resource_group.read", "resource_group.manage",
			"share.read", "share.offer", "share.accept", "share.revoke",
		),
	},
	BuiltinRoleITAdmin: {
		networkScopeAllowed: true,
		assignableBy:        []RoleAssigner{RoleAssignerOwner, RoleAssignerAdmin, RoleAssignerITAdmin},
		permissions: permissionsOf(
			"workspace.read", "member.read", "member.invite", "member.manage",
			"identity_provider.manage", "identity_group.manage", "identity_group.read",
			"device_tag.read", "device_tag.manage", "interchange.read", "interchange.manage",
			"role_definition.read", "role_binding.read", "role_binding.manage", "access_review.manage",
			"isolation.read", "guardrail.read", "audit.read",
			"network.read", "network.member.manage",
			"device.read", "device.manage", "device.transfer", "device.quarantine",
			"session.revoke", "enrollment_profile.read", "enrollment_profile.manage",
			"enrollment_credential.issue", "enrollment_credential.revoke",
			"device_group.read", "device_group.manage", "device_group.members.manage",
			"device_group.delegation.manage",
			"policy.read", "policy.explain", "route.read", "connector.read",
			"resource.read", "resource_group.read", "share.read",
		),
	},
	BuiltinRoleBillingAdmin: {
		assignableBy: []RoleAssigner{RoleAssignerOwner, RoleAssignerAdmin, RoleAssignerITAdmin},
		permissions:  permissionsOf("workspace.read", "billing.read", "billing.manage"),
	},
	BuiltinRoleAuditor: {
		networkScopeAllowed: true,
		assignableBy:        []RoleAssigner{RoleAssignerOwner, RoleAssignerAdmin, RoleAssignerITAdmin},
		// Every read permission in Workspace or Network scope, plus export.
		permissions: permissionsOf(
			"workspace.read", "member.read", "role_definition.read", "role_binding.read",
			"support.grant.read", "billing.read", "isolation.read", "guardrail.read",
			"identity_group.read", "device_tag.read", "interchange.read",
			"audit.read", "audit.export",
			"network.read", "device.read", "enrollment_profile.read", "device_group.read",
			"policy.read", "policy.validate", "policy.explain", "route.read", "connector.read",
			"resource.read", "resource_group.read", "share.read",
		),
	},
	BuiltinRoleSecurityAdmin: {
		assignableBy: []RoleAssigner{RoleAssignerOwner, RoleAssignerAdmin},
		permissions: permissionsOf(
			"workspace.read", "member.read", "role_definition.read", "role_binding.read",
			"isolation.read", "guardrail.read", "guardrail.manage", "guardrail.weaken",
			"identity_group.read", "device_tag.read", "interchange.read",
			"audit.read", "audit.export",
			"network.read", "device.read", "policy.read", "policy.explain",
			"resource.read", "resource_group.read", "share.read",
		),
	},
}

func permissionsOf(keys ...string) []Permission {
	permissions := make([]Permission, len(keys))
	for index, key := range keys {
		permissions[index] = Permission(key)
	}
	return permissions
}

// BuiltinRoles returns every assignable built-in role in stable order.
func BuiltinRoles() []BuiltinRole {
	return []BuiltinRole{
		BuiltinRoleAdmin, BuiltinRoleNetworkAdmin, BuiltinRoleITAdmin,
		BuiltinRoleBillingAdmin, BuiltinRoleAuditor, BuiltinRoleSecurityAdmin,
	}
}

// ParseBuiltinRole validates an exact role key.
func ParseBuiltinRole(value string) (BuiltinRole, error) {
	role := BuiltinRole(value)
	if _, exists := builtinRoleCatalog[role]; !exists {
		return "", ErrUnknownBuiltinRole
	}
	return role, nil
}

// IsValid reports whether the role is in the built-in catalog.
func (role BuiltinRole) IsValid() bool {
	_, exists := builtinRoleCatalog[role]
	return exists
}

// NetworkScopeAllowed reports whether the role may be bound to one Network.
func (role BuiltinRole) NetworkScopeAllowed() bool {
	return builtinRoleCatalog[role].networkScopeAllowed
}

// Permissions returns a caller-owned copy of the role's permission set.
func (role BuiltinRole) Permissions() []Permission {
	return slices.Clone(builtinRoleCatalog[role].permissions)
}

// Grants reports whether the role includes the permission.
func (role BuiltinRole) Grants(permission Permission) bool {
	return slices.Contains(builtinRoleCatalog[role].permissions, permission)
}

// AssignableBy reports whether an assigner may assign or revoke this role.
// Nobody assigns ownership; it changes only through owner transfer.
func (role BuiltinRole) AssignableBy(assigner RoleAssigner) bool {
	return slices.Contains(builtinRoleCatalog[role].assignableBy, assigner)
}

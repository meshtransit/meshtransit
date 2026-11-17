package migrations

import (
	"slices"
	"testing"
)

// Each operator login logs in as a serving role and is a member only of
// serving roles (TD-SEC-90 S1); the allowed memberships are exactly theirs.
func TestOperatorLoginsAreServingRoles(t *testing.T) {
	t.Parallel()
	logins := OperatorLogins()
	if len(logins) == 0 {
		t.Fatal("no operator login")
	}
	allowed := OperatorAllowedMemberships()
	for _, login := range logins {
		if !slices.Contains(OperatorApplicationRoles(), login.Name) {
			t.Errorf("%s is not an application role", login.Name)
		}
		for _, role := range login.MemberOf {
			if role == login.Name || !slices.Contains([]string{"mesh_runtime"}, role) {
				t.Errorf("%s is a member of %s, not a serving role it may inherit", login.Name, role)
			}
			if !slices.Contains(allowed, login.Name+" is a member of "+role) {
				t.Errorf("membership %s of %s is not allowed", role, login.Name)
			}
		}
	}
	logins[0].MemberOf[0] = "changed"
	if OperatorLogins()[0].MemberOf[0] == "changed" {
		t.Fatal("OperatorLogins must return copies")
	}
}

// Release N0 of S2 (role isolation design §3.5): the group roles are managed
// roles a step may grant to but never create, own with or log in as, and the
// memberships S2.2 adds are allowed one release early.
func TestOperatorGroupRolesAndLaterMemberships(t *testing.T) {
	t.Parallel()
	groups := OperatorGroupRoles()
	if !slices.Equal(groups, []string{"mesh_api_rights", "mesh_control_rights"}) {
		t.Fatalf("OperatorGroupRoles() = %v", groups)
	}
	managed, err := OperatorManagedRoles()
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range groups {
		if !slices.Contains(managed, group) {
			t.Errorf("group role %s is not a managed role", group)
		}
		if slices.Contains(OperatorApplicationRoles(), group) {
			t.Errorf("group role %s is an application role (it would log in)", group)
		}
	}
	allowed := OperatorAllowedMemberships()
	for _, membership := range []string{
		"mesh_control is a member of mesh_runtime",
		"mesh_runtime is a member of mesh_api_rights",
		"mesh_control is a member of mesh_control_rights",
		"mesh_all is a member of mesh_api_rights",
		"mesh_all is a member of mesh_control_rights",
		"mesh_all is a member of mesh_runtime",
	} {
		if !slices.Contains(allowed, membership) {
			t.Errorf("%q is not allowed", membership)
		}
	}
	for _, forbidden := range []string{
		"mesh_runtime is a member of mesh_control_rights",
		"mesh_control is a member of mesh_api_rights",
		"mesh_worker is a member of mesh_api_rights",
		"mesh_runtime is a member of mesh_migrator",
	} {
		if slices.Contains(allowed, forbidden) {
			t.Errorf("%q must not be allowed", forbidden)
		}
	}
	if len(allowed) != len(slices.Compact(slices.Sorted(slices.Values(allowed)))) {
		t.Errorf("allowed memberships repeat: %v", allowed)
	}
	groups[0] = "changed"
	if OperatorGroupRoles()[0] == "changed" {
		t.Fatal("OperatorGroupRoles must return a copy")
	}

	role := OperatorStep{Name: "000999_group_role", Kind: OperatorStepRole,
		Effects: []OperatorEffect{{Kind: OperatorEffectRole, Role: "mesh_api_rights"}}}
	if err := validateOperatorRoles([]OperatorStep{role}); err == nil {
		t.Error("a role step may create a group role")
	}
	grant := OperatorStep{Name: "000999_group_grant", Kind: OperatorStepOwnership,
		Effects: []OperatorEffect{{Kind: OperatorEffectExecute, Function: "mesh_ops.example_v1", Role: "mesh_control_rights"}}}
	if err := validateOperatorRoles([]OperatorStep{grant}); err != nil {
		t.Errorf("a step granting to a group role was refused: %v", err)
	}
}

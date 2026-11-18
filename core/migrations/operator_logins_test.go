package migrations

import (
	"regexp"
	"slices"
	"strings"
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
		for _, role := range slices.Concat(login.MemberOf, login.CreatedMemberOf) {
			if role == login.Name ||
				!slices.Contains([]string{"mesh_runtime", "mesh_api_rights", "mesh_control_rights"}, role) {
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

// S2.2 (role isolation design §3.5): each serving login is a member of its
// role's group and still of mesh_runtime, so nothing it may do changes in
// this release; mesh_runtime joins the api's group as an existing role.
func TestOperatorS22Memberships(t *testing.T) {
	t.Parallel()
	want := map[string][]string{
		"mesh_control": {"mesh_control_rights"},
		"mesh_all":     {"mesh_api_rights", "mesh_control_rights"},
	}
	logins := OperatorLogins()
	if len(logins) != len(want) {
		t.Fatalf("OperatorLogins() = %v", logins)
	}
	for _, login := range logins {
		if !slices.Equal(login.MemberOf, want[login.Name]) {
			t.Errorf("%s is a member of %v, want %v", login.Name, login.MemberOf, want[login.Name])
		}
		// mesh_runtime only when the apply creates the login: never added
		// back after S2.3 removed it (review blocker).
		if !slices.Equal(login.CreatedMemberOf, []string{"mesh_runtime"}) {
			t.Errorf("%s joins %v on creation, want mesh_runtime", login.Name, login.CreatedMemberOf)
		}
	}
	for _, membership := range []string{"mesh_control is a member of mesh_runtime", "mesh_all is a member of mesh_runtime"} {
		if !slices.Contains(OperatorAllowedMemberships(), membership) {
			t.Errorf("%q is not allowed", membership)
		}
	}
	if got := OperatorRoleMemberships(); !slices.Equal(got,
		[]OperatorMembership{{Member: "mesh_runtime", Of: "mesh_api_rights"}}) {
		t.Errorf("OperatorRoleMemberships() = %v", got)
	}
	for login, groups := range map[string][]string{
		"mesh_runtime": {"mesh_api_rights"},
		"mesh_control": {"mesh_control_rights"},
		"mesh_all":     {"mesh_api_rights", "mesh_control_rights"},
		"mesh_worker":  {},
		"mesh_unknown": {},
	} {
		if got := OperatorRequiredGroups(login); !slices.Equal(got, groups) {
			t.Errorf("OperatorRequiredGroups(%s) = %v, want %v", login, got, groups)
		}
	}
	if !slices.Contains(OperatorApplicationRoles(), "mesh_all") {
		t.Error("mesh_all is not an application role")
	}
}

var operatorRuntimeGrant = regexp.MustCompile(
	`(?is)GRANT\s+EXECUTE\s+ON\s+FUNCTION\s+([a-z_.0-9]+)\s*\([^;]*?\)\s*TO\s+([a-z_, ]+);`)

// The retired list is exactly the operator-owned functions a step granted
// to mesh_runtime that neither the api nor control calls (D1): a missing
// entry would let S2.3's narrowing be undone after a rollback; an extra one
// would let a step that never ran count as applied.
func TestOperatorRetiredRuntimeFunctionsMatchManifest(t *testing.T) {
	t.Parallel()
	manifest, err := RoleGrants()
	if err != nil {
		t.Fatal(err)
	}
	used := append(slices.Clone(manifest["api"].Functions), manifest["control"].Functions...)
	steps, err := OperatorSteps()
	if err != nil {
		t.Fatal(err)
	}
	retired := []string{}
	for _, step := range steps {
		for _, match := range operatorRuntimeGrant.FindAllStringSubmatch(step.Body(), -1) {
			name := strings.ToLower(match[1])
			if strings.Contains(match[2], "mesh_runtime") && !slices.Contains(used, name) &&
				!slices.Contains(retired, name) {
				retired = append(retired, name)
			}
		}
	}
	slices.Sort(retired)
	if !slices.Equal(retired, operatorRetiredRuntimeFunctions) {
		t.Errorf("retired functions = %v, want %v", operatorRetiredRuntimeFunctions, retired)
	}
	if !OperatorRuntimeRetired("mesh_ops.revoke_resource_share_v1(uuid)") ||
		OperatorRuntimeRetired("mesh_ops.revoke_resource_share_v6(uuid)") {
		t.Error("OperatorRuntimeRetired does not match by name")
	}
}

// firstGroupOnlyVersion is the first schema version of role isolation S2.2:
// from it, migrations and operator steps grant only to the group roles
// (role isolation design §3.1), never to a login.
const firstGroupOnlyVersion = 297

var loginGrant = regexp.MustCompile(
	`(?is)\bGRANT\b[^;]*?\bTO\b[^;]*?\b(mesh_runtime|mesh_control|mesh_all)\b`)

func TestNoGrantToLoginsFromS22(t *testing.T) {
	t.Parallel()
	for _, migration := range Catalog() {
		if migration.Version < firstGroupOnlyVersion {
			continue
		}
		if match := loginGrant.FindString(migration.SQL); match != "" {
			t.Errorf("migration %d grants to a login: %q", migration.Version, match)
		}
	}
	steps, err := OperatorSteps()
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range steps {
		if step.Version < firstGroupOnlyVersion {
			continue
		}
		if match := loginGrant.FindString(step.Body()); match != "" {
			t.Errorf("operator step %s grants to a login: %q", step.Name, match)
		}
	}
	if loginGrant.FindString("GRANT EXECUTE ON FUNCTION mesh_ops.f_v1(UUID) TO mesh_api_rights;") != "" ||
		loginGrant.FindString("GRANT EXECUTE ON FUNCTION mesh_ops.f_v1(UUID)\n TO mesh_runtime;") == "" {
		t.Error("the login grant pattern is wrong")
	}
}

// Migration 298 leaves every operator-managed function family to operator
// step 298: its list holds each family a step of schema 298 or earlier
// hands to an owner role.
func TestGroupGrantsMigrationSkipsOperatorFamilies(t *testing.T) {
	t.Parallel()
	migration := Catalog()[297]
	if migration.Version != 298 {
		t.Fatalf("migration 298 version = %d", migration.Version)
	}
	steps, err := OperatorSteps()
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range steps {
		if step.Version > 298 {
			continue
		}
		for _, effect := range step.Effects {
			if effect.Kind != OperatorEffectOwner {
				continue
			}
			name, _, _ := strings.Cut(strings.TrimPrefix(effect.Function, "mesh_ops."), "(")
			family := operatorFunctionVersion.ReplaceAllString(name, "")
			if !strings.Contains(migration.SQL, "'"+family+"'") {
				t.Errorf("migration 298 does not leave %s to the operator", family)
			}
		}
	}
}

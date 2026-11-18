package migrations

import (
	"slices"
	"strings"
)

// OperatorLogin is a serving login the operator command creates and keeps
// (role isolation design §3.4, TD-SEC-90 step S1): its own name and
// password, and the privileges of the roles it is a member of (INHERIT, no
// SET). A login is kept only when the apply is given its password.
//
// Step S2.2 (§3.5) adds the group roles: each login is a member of its
// role's group (MemberOf, kept on every apply) and, when the apply creates
// it, of mesh_runtime too (CreatedMemberOf), so the privileges in effect do
// not change in this release. A creation-only membership is kept but never
// added again: step S2.3 removes it, and an apply of this release after a
// rollback must not give it back (control would inherit the api's rights).
type OperatorLogin struct {
	Name            string
	MemberOf        []string
	CreatedMemberOf []string
}

var operatorLogins = []OperatorLogin{
	{Name: "mesh_control", MemberOf: []string{"mesh_control_rights"}, CreatedMemberOf: []string{"mesh_runtime"}},
	// mesh_all is the self-host login: one process runs every role.
	{Name: "mesh_all", MemberOf: []string{"mesh_api_rights", "mesh_control_rights"},
		CreatedMemberOf: []string{"mesh_runtime"}},
}

// OperatorLogins returns the logins the operator command keeps, in order.
func OperatorLogins() []OperatorLogin {
	logins := make([]OperatorLogin, len(operatorLogins))
	for index, login := range operatorLogins {
		logins[index] = OperatorLogin{Name: login.Name, MemberOf: slices.Clone(login.MemberOf),
			CreatedMemberOf: slices.Clone(login.CreatedMemberOf)}
	}
	return logins
}

// OperatorMembership is a membership the operator command keeps on a role
// it does not create or log in as: mesh_runtime, the api's login, existed
// before the login catalog and keeps its own password.
type OperatorMembership struct {
	Member string
	Of     string
}

var operatorRoleMemberships = []OperatorMembership{
	{Member: "mesh_runtime", Of: "mesh_api_rights"},
}

// OperatorRoleMemberships returns the memberships the operator command keeps
// on existing roles, in order.
func OperatorRoleMemberships() []OperatorMembership { return slices.Clone(operatorRoleMemberships) }

// operatorGroupRoles are the NOLOGIN group roles of step S2 (role isolation
// design §3.5): from S2.2 every grant of a serving role goes to its group and
// a login gets it through membership. The operator command creates them
// (release N0) before any migration grants to them.
var operatorGroupRoles = []string{"mesh_api_rights", "mesh_control_rights"}

// operatorLaterMemberships are memberships a later release adds, allowed
// one release early so the pods and migrations of this release still pass
// their checks once the membership exists and after a rollback (§3.5 N0).
// S2.2 made those of N0 part of the catalogs; S2.3 adds none.
var operatorLaterMemberships = []string{}

// OperatorGroupRoles returns the group roles the operator command keeps.
func OperatorGroupRoles() []string { return slices.Clone(operatorGroupRoles) }

// OperatorAllowedMemberships returns the only memberships MeshTransit roles
// may take part in, as the operator report spells them ("x is a member of
// y"): those of OperatorLogins, of OperatorRoleMemberships and those a later
// release adds. Any other is reported.
func OperatorAllowedMemberships() []string {
	allowed := []string{}
	add := func(membership string) {
		if !slices.Contains(allowed, membership) {
			allowed = append(allowed, membership)
		}
	}
	for _, login := range operatorLogins {
		for _, role := range slices.Concat(login.MemberOf, login.CreatedMemberOf) {
			add(login.Name + " is a member of " + role)
		}
	}
	for _, membership := range operatorRoleMemberships {
		add(membership.Member + " is a member of " + membership.Of)
	}
	for _, membership := range operatorLaterMemberships {
		add(membership)
	}
	return allowed
}

// operatorRuntimeHolders are the roles through which an operator step's
// EXECUTE for mesh_runtime still counts as held (§3.5 S2.2, decision D1):
// mesh_runtime itself, directly or through its group, and the control's
// group. Step S2.3 takes mesh_runtime's direct grants away; an operator
// command of this release, after a rollback, must not grant them again.
var operatorRuntimeHolders = []string{"mesh_runtime", "mesh_api_rights", "mesh_control_rights"}

// OperatorRuntimeHolders returns the roles that hold an EXECUTE a step
// grants to mesh_runtime.
func OperatorRuntimeHolders() []string { return slices.Clone(operatorRuntimeHolders) }

// operatorRetiredRuntimeFunctions are the operator-owned function versions a
// step granted to mesh_runtime that neither the api nor control calls any
// more (core/migrations/role_grants.json, a test keeps the list exact). Their
// EXECUTE for mesh_runtime counts as held whether or not it exists: S2.3
// takes it away, and nothing may grant it back.
var operatorRetiredRuntimeFunctions = []string{
	"mesh_ops.activate_resource_share_v1",
	"mesh_ops.activate_resource_share_v2",
	"mesh_ops.activate_resource_share_v3",
	"mesh_ops.create_resource_share_offer_v1",
	"mesh_ops.create_resource_share_offer_v2",
	"mesh_ops.decide_resource_share_offer_v1",
	"mesh_ops.decide_resource_share_offer_v2",
	"mesh_ops.decide_resource_share_offer_v3",
	"mesh_ops.flowlog_destination_v1",
	"mesh_ops.flowlog_receiver_gate_v1",
	"mesh_ops.flowlog_report_status_v1",
	"mesh_ops.load_device_alias_map_edges_v1",
	"mesh_ops.load_device_alias_map_edges_v2",
	"mesh_ops.revoke_resource_share_v1",
	"mesh_ops.revoke_resource_share_v2",
	"mesh_ops.revoke_resource_share_v3",
	"mesh_ops.revoke_resource_share_v4",
	"mesh_ops.revoke_resource_share_v5",
}

// OperatorRuntimeRetired reports whether a step's EXECUTE for mesh_runtime
// on the function of signature is retired.
func OperatorRuntimeRetired(signature string) bool {
	name, _, _ := strings.Cut(signature, "(")
	return slices.Contains(operatorRetiredRuntimeFunctions, name)
}

// OperatorRequiredGroups returns the group roles a serving login must be a
// member of to serve (§3.5 S2.2): the groups of its catalog entry, none for
// a login outside the catalogs (the worker).
func OperatorRequiredGroups(login string) []string {
	groups := []string{}
	add := func(role string) {
		if slices.Contains(operatorGroupRoles, role) && !slices.Contains(groups, role) {
			groups = append(groups, role)
		}
	}
	for _, entry := range operatorLogins {
		if entry.Name == login {
			for _, role := range entry.MemberOf {
				add(role)
			}
		}
	}
	for _, membership := range operatorRoleMemberships {
		if membership.Member == login {
			add(membership.Of)
		}
	}
	return groups
}

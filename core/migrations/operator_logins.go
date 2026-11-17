package migrations

import "slices"

// OperatorLogin is a serving login the operator command creates and keeps
// (role isolation design §3.4, TD-SEC-90 step S1): its own name and
// password, and the privileges of the roles it is a member of (INHERIT, no
// SET). Until step S2 gives each login its own group of explicit grants,
// mesh_control is a member of mesh_runtime, so control keeps exactly the
// privileges and RLS policies it has today under a separate credential.
type OperatorLogin struct {
	Name     string
	MemberOf []string
}

var operatorLogins = []OperatorLogin{
	{Name: "mesh_control", MemberOf: []string{"mesh_runtime"}},
}

// OperatorLogins returns the logins the operator command keeps, in order.
func OperatorLogins() []OperatorLogin {
	logins := make([]OperatorLogin, len(operatorLogins))
	for index, login := range operatorLogins {
		logins[index] = OperatorLogin{Name: login.Name, MemberOf: slices.Clone(login.MemberOf)}
	}
	return logins
}

// operatorGroupRoles are the NOLOGIN group roles of step S2 (role isolation
// design §3.5): from S2.2 every grant of a serving role goes to its group and
// a login gets it through membership. The operator command creates them
// (release N0) before any migration grants to them.
var operatorGroupRoles = []string{"mesh_api_rights", "mesh_control_rights"}

// operatorLaterMemberships are memberships a later release adds (S2.2):
// allowed one release early, so the pods and migrations of this release
// still pass their checks once the membership exists and after a rollback
// (§3.5 N0). mesh_all is the self-host login that runs every role.
var operatorLaterMemberships = []string{
	"mesh_runtime is a member of mesh_api_rights",
	"mesh_control is a member of mesh_control_rights",
	"mesh_all is a member of mesh_api_rights",
	"mesh_all is a member of mesh_control_rights",
	"mesh_all is a member of mesh_runtime",
}

// OperatorGroupRoles returns the group roles the operator command keeps.
func OperatorGroupRoles() []string { return slices.Clone(operatorGroupRoles) }

// OperatorAllowedMemberships returns the only memberships MeshTransit roles
// may take part in, as the operator report spells them ("x is a member of
// y"): those of OperatorLogins and those a later release adds. Any other is
// reported.
func OperatorAllowedMemberships() []string {
	allowed := []string{}
	for _, login := range operatorLogins {
		for _, role := range login.MemberOf {
			allowed = append(allowed, login.Name+" is a member of "+role)
		}
	}
	for _, membership := range operatorLaterMemberships {
		if !slices.Contains(allowed, membership) {
			allowed = append(allowed, membership)
		}
	}
	return allowed
}

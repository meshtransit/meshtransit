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

// OperatorAllowedMemberships returns the only memberships MeshTransit roles
// may take part in, as the operator report spells them ("x is a member of
// y"): those of OperatorLogins. Any other is reported.
func OperatorAllowedMemberships() []string {
	allowed := []string{}
	for _, login := range operatorLogins {
		for _, role := range login.MemberOf {
			allowed = append(allowed, login.Name+" is a member of "+role)
		}
	}
	return allowed
}

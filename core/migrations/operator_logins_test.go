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

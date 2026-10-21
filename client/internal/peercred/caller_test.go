package peercred

import "testing"

func TestCallerIsOperator(t *testing.T) {
	t.Parallel()
	const operators = "S-1-5-21-1-2-3-1001"
	admin := "S-1-5-21-1-2-3-500"
	member := "S-1-5-21-1-2-3-1002"
	for _, test := range []struct {
		name      string
		caller    Caller
		operators string
		want      bool
	}{
		{"local system", Caller{UserSID: SIDLocalSystem}, "", true},
		{"elevated administrator", Caller{UserSID: admin, Groups: []Group{{SIDAdministrators, true}}}, "", true},
		{"filtered administrator", Caller{UserSID: admin, Groups: []Group{{SIDAdministrators, false}}}, "", false},
		{"operators member", Caller{UserSID: member, Groups: []Group{{operators, true}}}, operators, true},
		{"operators group missing", Caller{UserSID: member, Groups: []Group{{operators, true}}}, "", false},
		{"ordinary user", Caller{UserSID: member, Groups: []Group{{"S-1-5-32-545", true}}}, operators, false},
	} {
		if got := test.caller.IsOperator(test.operators); got != test.want {
			t.Errorf("%s: IsOperator() = %t, want %t", test.name, got, test.want)
		}
	}
}

func TestCallerIsAdministrator(t *testing.T) {
	t.Parallel()
	const operators = "S-1-5-21-1-2-3-1001"
	member := "S-1-5-21-1-2-3-1002"
	if !(Caller{UserSID: SIDLocalSystem}).IsAdministrator() {
		t.Error("LocalSystem is no administrator")
	}
	if !(Caller{UserSID: member, Groups: []Group{{SIDAdministrators, true}}}).IsAdministrator() {
		t.Error("an elevated administrator is no administrator")
	}
	if (Caller{UserSID: member, Groups: []Group{{SIDAdministrators, false}, {operators, true}}}).IsAdministrator() {
		t.Error("an operator with a filtered administrator token is an administrator")
	}
}

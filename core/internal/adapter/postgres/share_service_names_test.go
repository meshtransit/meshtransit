package postgres

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/sharing"
)

func TestApprovedServiceNames(t *testing.T) {
	t.Parallel()
	name := func(value string) sharing.ServiceName {
		parsed, err := sharing.ParseServiceName(value)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	suggested := []sharing.ServiceName{name("app.corp.com"), name("wiki.corp.lan"), name("sso.corp.lan")}
	approved, places, err := approvedServiceNames(suggested, []sharing.ServiceNameDecision{
		{Name: name("sso.corp.lan"), Approve: true}, {Name: name("app.corp.com"), Approve: true},
		{Name: name("wiki.corp.lan")},
	})
	if err != nil || len(approved) != 2 || approved[0] != name("app.corp.com") || places[0] != 1 ||
		approved[1] != name("sso.corp.lan") || places[1] != 0 {
		t.Fatalf("approved = %v at %v, %v", approved, places, err)
	}
	for label, decisions := range map[string][]sharing.ServiceNameDecision{
		"one missing": {{Name: name("app.corp.com")}, {Name: name("wiki.corp.lan")}},
		"one not suggested": {{Name: name("app.corp.com")}, {Name: name("wiki.corp.lan")},
			{Name: name("other.corp.lan")}},
	} {
		if _, _, err := approvedServiceNames(suggested, decisions); !errors.Is(err, sharing.ErrServiceNameDecisions) {
			t.Errorf("%s: %v", label, err)
		}
	}
	if approved, _, err := approvedServiceNames(nil, nil); err != nil || len(approved) != 0 {
		t.Fatal("an offer without names")
	}
}

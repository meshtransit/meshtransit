package sharing

import (
	"strings"
	"testing"
)

func TestParseServiceName(t *testing.T) {
	t.Parallel()
	for _, valid := range []string{"app.corp.com", "a.b", "xn--bcher-kva.example.org"} {
		if name, err := ParseServiceName(valid); err != nil || name.String() != valid || !name.IsValid() {
			t.Errorf("%q: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		"", "app", "App.corp.com", "app.corp.com.", " app.corp.com", "10.0.0.1", "1.2", "-a.corp.com",
		strings.Repeat("a", 64) + ".com", "a..b",
	} {
		if _, err := ParseServiceName(invalid); err == nil {
			t.Errorf("%q: accepted", invalid)
		}
	}
	if (ServiceName{}).IsValid() {
		t.Error("the zero name is valid")
	}
}

func TestServiceNameBounds(t *testing.T) {
	t.Parallel()
	name := func(value string) ServiceName {
		parsed, err := ParseServiceName(value)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	eight := make([]ServiceName, 0, MaximumServiceNames+1)
	for index := range MaximumServiceNames {
		eight = append(eight, name(string(rune('a'+index))+".corp.com"))
	}
	if !validServiceNames(eight) || validServiceNames(append(eight, name("z.corp.com"))) {
		t.Error("eight names are the most an offer suggests")
	}
	if validServiceNames([]ServiceName{name("a.corp.com"), name("a.corp.com")}) {
		t.Error("a name suggested twice")
	}
	if validServiceNameDecisions([]ServiceNameDecision{{Name: name("a.corp.com")}, {Name: name("a.corp.com"),
		Approve: true}}) {
		t.Error("a name answered twice")
	}
	if validServiceNameDecisions([]ServiceNameDecision{{}}) {
		t.Error("an answer without a name")
	}
}

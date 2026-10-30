package kubeprofile

import (
	"errors"
	"fmt"
	"testing"
)

// Maps name scopes by this hash on both sides: its encoding must never
// change silently (mtcp-v1 §7.12).
func TestScopeHashKnownAnswer(t *testing.T) {
	t.Parallel()
	profile, err := ContentHash(developer())
	if err != nil {
		t.Fatal(err)
	}
	hash, err := ScopeHash(profile, []string{"team-b", "team-a"}, true)
	if err != nil || fmt.Sprintf("%x", hash) != "98854cf3321a6507cda6499cd811740a836557e1d679ea651784f9d4d552faa4" {
		t.Fatalf("ScopeHash = %x (%v)", hash, err)
	}
	for name, other := range map[string]func() ([32]byte, error){
		"other namespaces": func() ([32]byte, error) { return ScopeHash(profile, []string{"team-a"}, true) },
		"cluster part off": func() ([32]byte, error) { return ScopeHash(profile, []string{"team-a", "team-b"}, false) },
		"other profile":    func() ([32]byte, error) { return ScopeHash([32]byte{1}, []string{"team-a", "team-b"}, true) },
		"every namespace":  func() ([32]byte, error) { return ScopeHash(profile, []string{"*"}, true) },
	} {
		if got, err := other(); err != nil || got == hash {
			t.Errorf("%s: %x (%v) equals the scope's hash", name, got, err)
		}
	}
	if again, err := ScopeHash(profile, []string{"team-a", "team-b", "team-a"}, true); err != nil || again != hash {
		t.Errorf("order and duplicates changed the hash: %x (%v)", again, err)
	}
	for name, namespaces := range map[string][]string{"none": nil, "star mixed": {"*", "a"}, "upper": {"A"}} {
		if _, err := ScopeHash(profile, namespaces, false); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: ScopeHash = %v, want ErrInvalid", name, err)
		}
	}
}

// The canonical form escapes only '"' and '\': the characters an encoder
// may escape its own way are refused.
func TestValidateRefusesEscapedCharacters(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"a<b", "a>b", "a&b"} {
		name := Profile{Name: "x", Namespaced: []Rule{{APIGroups: []string{""}, Resources: []string{"pods"},
			Verbs: []string{"get"}, ResourceNames: []string{value}}}}
		path := Profile{Name: "x", Cluster: []Rule{{NonResourceURLs: []string{"/" + value}, Verbs: []string{"get"}}}}
		for kind, profile := range map[string]Profile{"name": name, "path": path} {
			if err := Validate(profile); !errors.Is(err, ErrInvalid) {
				t.Errorf("%s %q: Validate = %v, want ErrInvalid", kind, value, err)
			}
		}
	}
	quoted := Profile{Name: "x", Namespaced: []Rule{{APIGroups: []string{""}, Resources: []string{"pods"},
		Verbs: []string{"get"}, ResourceNames: []string{`a"b\c`}}}}
	if err := Validate(quoted); err != nil {
		t.Errorf("a name with a quote and a backslash: %v", err)
	}
}

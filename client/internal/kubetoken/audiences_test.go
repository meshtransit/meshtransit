package kubetoken

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// writeToken writes a token whose claims are claims, with content around it.
func writeToken(t *testing.T, around, claims string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	token := "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(claims)) + ".c2ln"
	if err := os.WriteFile(path, []byte(around+token+around), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// The API server's audiences are read from a token, as a string or a list;
// anything else is an error naming what is wrong.
func TestReadAudiences(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		around, claims string
		want           []string
		err            error
	}{
		"list":          {"", `{"aud":["https://kubernetes.default.svc","api"]}`, []string{"https://kubernetes.default.svc", "api"}, nil},
		"string":        {"\n ", `{"aud":"https://kubernetes.default.svc.cluster.local"}`, []string{"https://kubernetes.default.svc.cluster.local"}, nil},
		"none":          {"", `{"sub":"x"}`, nil, ErrNoAudiences},
		"null":          {"", `{"aud":null}`, nil, ErrNoAudiences},
		"empty list":    {"", `{"aud":[]}`, nil, ErrNoAudiences},
		"blank":         {"", `{"aud":""}`, nil, ErrNoAudiences},
		"blank in list": {"", `{"aud":["a",""]}`, nil, ErrNoAudiences},
		"mixed list":    {"", `{"aud":["a",7]}`, nil, ErrNoAudiences},
		"number":        {"", `{"aud":7}`, nil, ErrNoAudiences},
		"not JSON":      {"", `not json`, nil, errClaimsNotJSON},
		"gateway token": {"", `{"aud":["meshtransit.net/kubernetes-gateway"]}`, nil, ErrNotAPIToken},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ReadAudiences(writeToken(t, test.around, test.claims))
			if !slices.Equal(got, test.want) || !errors.Is(err, test.err) {
				t.Fatalf("%q, %v; want %q, %v", got, err, test.want, test.err)
			}
		})
	}
	dir := t.TempDir()
	for name, content := range map[string]string{
		"not a JWT": "not a jwt", "one dot": "a.b", "empty part": "a..c",
		"too large": strings.Repeat("a", maximumTokenFile+1),
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadAudiences(path); err == nil {
			t.Errorf("%s: read", name)
		}
	}
	if _, err := ReadAudiences(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file was read")
	}
}

// Audiences compare as sets.
func TestSameAudiences(t *testing.T) {
	t.Parallel()
	if !SameAudiences([]string{"b", "a"}, []string{"a", "b", "a"}) {
		t.Error("the same set differs")
	}
	if SameAudiences([]string{"a"}, []string{"a", "b"}) || SameAudiences(nil, []string{"a"}) {
		t.Error("different sets are equal")
	}
}

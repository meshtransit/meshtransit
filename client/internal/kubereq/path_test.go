package kubereq

import (
	"strings"
	"testing"
)

// Only plain paths reach the API server: printable ASCII without "%",
// "\", empty (but for one trailing "/"), "." or ".." segments (K1b design
// §5).
func TestCheckPath(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/api", "/api/v1/namespaces/default/pods/web-0", "/apis/rbac.authorization.k8s.io/v1/clusterroles/system:aggregate-to-admin",
		"/version", "/openapi/v3/apis/apps/v1", "/.well-known/openid-configuration", "/api/",
		"/api/v1/namespaces/a/services/web:80/proxy/",
	} {
		if err := CheckPath(path); err != nil {
			t.Errorf("%q: %v", path, err)
		}
	}
	for _, path := range []string{
		"", "api", "/", "//api", "/api//", "/api/v1/../", "/api//v1", "/api/./v1", "/api/../v1", "/api/v1/..", "/api/%2e%2e",
		"/api/v1/pods/a%2Fb", "/api/v1/pods/a b", "/api/v1/pods/\x00", "/api/v1/pods/é", "/api\\v1",
		"/" + strings.Repeat("a", 4097),
	} {
		if err := CheckPath(path); err == nil {
			t.Errorf("%q: taken", path)
		}
	}
}

// /mt/g/<group>/ names a group; what follows must be an API path.
func TestSplitGroup(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		path, group, rest string
		ok                bool
	}{
		{"/api/v1/pods", "", "/api/v1/pods", true},
		{"/mt/g/sre/api/v1/pods", "sre", "/api/v1/pods", true},
		{"/mt/g/sre/apis/apps/v1", "sre", "/apis/apps/v1", true},
		{"/mt/g/sre/version", "sre", "/version", true},
		{"/mt/g/sre", "", "", false},
		{"/mt/g/sre/", "", "", false},
		{"/mt/g/sre/mt/g/x/api", "", "", false},
		{"/mt/g/sre/healthzz", "", "", false},
		{"/mt/g/Bad_Name/api", "", "", false},
		{"/mt/v1/whoami", "", "", false},
		{"/mt/g//api", "", "", false},
		{"/mt", "", "/mt", true}, // not under /mt/: the default group's, then unparsed
		{"/mt/g/sre/openapi/v3/apis/apps/v1", "sre", "/openapi/v3/apis/apps/v1", true},
		{"/mt/g/sre/api/", "sre", "/api/", true},
	} {
		group, rest, ok := SplitGroup(test.path)
		if group != test.group || rest != test.rest || ok != test.ok {
			t.Errorf("%q: %q %q %t", test.path, group, rest, ok)
		}
	}
}

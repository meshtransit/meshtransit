package kubereq

import (
	"net/http"
	"net/url"
	"testing"
)

// Parsing and classifying never panic; a read is a GET or HEAD (or a
// self-review's POST) that neither upgrades, proxies, opens a session nor
// reads a secret-like resource; a request that does not parse is type A;
// SplitGroup never forwards a path CheckPath would refuse.
func FuzzClassify(f *testing.F) {
	for _, seed := range []string{
		"/api/v1/namespaces/a/pods/b/exec?command=sh", "/apis/g/v/watch/r", "/api/v1/proxy/namespaces/a/pods/b/c",
		"/mt/g/sre/api/v1/secrets?fieldSelector=metadata.name%3Dx", "/api/v1/namespaces/a/secrets?watch=0",
		"/apis/a/b/namespaces", "/api/v1/namespaces/a/finalize", "/apis/s.io/v1/namespaces/a/vaults/v/status",
		"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews",
	} {
		for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete, "PROPFIND"} {
			f.Add(method, seed, "", "")
		}
	}
	f.Add(http.MethodGet, "/api/v1/pods", "upgrade", "websocket")
	f.Fuzz(func(t *testing.T, method, raw, connection, upgrade string) {
		target, err := url.Parse(raw)
		if err != nil {
			return
		}
		header := http.Header{}
		if connection != "" {
			header.Set("Connection", connection)
		}
		if upgrade != "" {
			header.Set("Upgrade", upgrade)
		}
		secretLike := []GroupResource{{Group: "s.io", Resource: "vaults"}}
		request := Request{Method: method, URL: target, Header: header}
		class, info := Classify(request, Options{SecretResources: secretLike})
		if class == "" {
			t.Fatalf("%s %q: no class", method, raw)
		}
		if _, err := Parse(method, target); err != nil && class != ClassUnparsed && !upgrades(request) {
			t.Fatalf("%s %q: an unparsed request classed %s", method, raw, class)
		}
		if class == ClassRead {
			resource := GroupResource{Group: info.APIGroup, Resource: info.Resource}
			selfReview := method == http.MethodPost && selfReviews[resource]
			switch {
			case method != http.MethodGet && method != http.MethodHead && !selfReview:
				t.Fatalf("%s %q: a read by %s", method, raw, method)
			case upgrades(request), info.Verb == "proxy", info.Subresource == "proxy", interactive[info.Subresource]:
				t.Fatalf("%s %q: a session or proxy read: %+v", method, raw, info)
			case info.IsResourceRequest && (resource == secrets || contains(secretLike, resource)):
				t.Fatalf("%s %q: a secret read as a read", method, raw)
			}
		}
		escaped := target.EscapedPath()
		if _, rest, ok := SplitGroup(escaped); ok && CheckPath(escaped) == nil && CheckPath(rest) != nil {
			t.Fatalf("%q: forwards a path it would refuse: %q", raw, rest)
		}
	})
}

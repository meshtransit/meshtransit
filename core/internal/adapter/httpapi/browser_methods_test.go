package httpapi

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// A change may also be a PUT, PATCH or DELETE: each carries the session
// headers, a PUT or PATCH a JSON body, a DELETE no body at all.
func TestBrowserManagementAdmitsRESTMethods(t *testing.T) {
	t.Parallel()
	browser, _ := newBrowserManagementFixture(t)
	path := "/api/v1/workspaces/" + managementWorkspaceID() + "/device-tags"
	for _, test := range []struct {
		name   string
		method string
		body   string
		header func(http.Header)
		valid  bool
	}{
		{"put", http.MethodPut, `{}`, nil, true},
		{"patch", http.MethodPatch, `{}`, nil, true},
		{"patch without a JSON type", http.MethodPatch, `{}`, func(h http.Header) { h.Set("Content-Type", "text/plain") }, false},
		{"delete", http.MethodDelete, "", func(h http.Header) { h.Del("Content-Type") }, true},
		{"delete with a body", http.MethodDelete, `{}`, func(h http.Header) { h.Del("Content-Type") }, false},
		{"delete with a content type", http.MethodDelete, "", nil, false},
		{"head", http.MethodHead, "", func(h http.Header) { h.Del("Content-Type") }, false},
		{"trace", http.MethodTrace, "", func(h http.Header) { h.Del("Content-Type") }, false},
		{"options", http.MethodOptions, "", func(h http.Header) { h.Del("Content-Type") }, false},
	} {
		request := browserManagementRequest(t, path, test.body)
		request.Method = test.method
		if test.body == "" {
			request.Body = http.NoBody
			request.ContentLength = 0
		} else {
			request.Body = io.NopCloser(strings.NewReader(test.body))
			request.ContentLength = int64(len(test.body))
		}
		request.Header.Set("X-MeshTransit-CSRF", "proof")
		if test.header != nil {
			test.header(request.Header)
		}
		if got := browser.validRequest(request); got != test.valid {
			t.Errorf("%s: valid = %t, want %t", test.name, got, test.valid)
		}
	}
}

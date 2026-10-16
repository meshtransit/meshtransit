package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

// The Console reaches the key list and both key actions through the
// account-session cookie, never with a query.
func TestBrowserManagementAdmitsEnrollmentKeyRoutes(t *testing.T) {
	t.Parallel()
	browser, _ := newBrowserManagementFixture(t)
	list := browserManagementReadRequest(t, enrollmentKeysTestPath(""))
	if !browser.validRequest(list) {
		t.Fatal("the browser cannot read the Network's enrollment keys")
	}
	for _, path := range []string{
		enrollmentKeysTestPath("/actions/create"),
		enrollmentKeysTestPath("/" + enrollmentKeyTestKey + "/actions/revoke"),
	} {
		if !browser.validRequest(browserManagementRequest(t, path, `{}`)) {
			t.Errorf("the browser cannot POST %s", path)
		}
	}
	for _, path := range []string{
		enrollmentKeysTestPath("?state=active"),
		enrollmentKeysTestPath("/actions/create"),
		enrollmentKeysTestPath("/" + enrollmentKeyTestKey + "/actions/revoke"),
	} {
		request := browserManagementReadRequest(t, path)
		request.Method = http.MethodGet
		if browser.validRequest(request) {
			t.Errorf("the browser admitted GET %s", path)
		}
	}
	if isBrowserManagementOperation(browserManagementRequest(t, enrollmentKeysTestPath(""), `{}`)) {
		t.Error("a POST to the key list is routed to browser management")
	}
}

func TestBrowserManagementServesEnrollmentKeys(t *testing.T) {
	t.Parallel()
	browser, fixture := newBrowserManagementFixture(t)
	list := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(list, browserManagementReadRequest(t, enrollmentKeysTestPath(""))); err != nil {
		t.Fatal(err)
	}
	if list.Code != http.StatusOK || fixture.enrollmentKeys.lists != 1 ||
		list.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("list = %d after %d store reads; %s", list.Code, fixture.enrollmentKeys.lists, list.Body)
	}

	request := browserManagementRequest(t, enrollmentKeysTestPath("/actions/create"), `{"device_never_expires":true}`)
	request.Header.Del("If-Match")
	request.Header.Del("Idempotency-Key")
	request.Header.Set("X-MeshTransit-CSRF", preparedBrowserProof(t, browser))
	created := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(created, request); err != nil {
		t.Fatal(err)
	}
	if created.Code != http.StatusCreated || len(fixture.enrollmentKeys.issued) != 1 ||
		!strings.Contains(created.Body.String(), `"secret":"mtc1.`) || created.Header().Get("Set-Cookie") != "" {
		t.Fatalf("create = %d; %s", created.Code, created.Body)
	}
}

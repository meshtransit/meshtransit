package rbaccheck

import (
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The reviewer posts a SelfSubjectAccessReview with the group's token and
// reads its answer; a refused token is ErrUnauthorized; anything else
// without a status is an error, never an "allowed: false".
func TestAPIReviewer(t *testing.T) {
	t.Parallel()
	var seen accessReview
	var auth string
	status := http.StatusCreated
	answer := `{"status":{"allowed":true}}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &seen)
		auth = r.Header.Get("Authorization")
		if r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
	t.Cleanup(server.Close)
	ca := filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
		Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	reviewer, err := NewAPIReviewer(server.URL, ca)
	if err != nil {
		t.Fatal(err)
	}
	attributes := Attributes{Namespace: "meshtransit", Verb: "get", Resource: "pods", Subresource: "exec",
		Name: "meshgw-0"}
	allowed, err := reviewer.Review(t.Context(), "token-view", attributes)
	if err != nil || !allowed || auth != "Bearer token-view" || seen.Kind != "SelfSubjectAccessReview" ||
		seen.Spec.ResourceAttributes.Subresource != "exec" || seen.Spec.ResourceAttributes.Name != "meshgw-0" {
		t.Fatalf("review %+v, %t, %v", seen, allowed, err)
	}
	status = http.StatusUnauthorized
	if _, err := reviewer.Review(t.Context(), "t", attributes); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("401: %v", err)
	}
	for _, failing := range []struct {
		status int
		answer string
	}{{http.StatusForbidden, ""}, {http.StatusCreated, `{}`}, {http.StatusCreated, `nope`},
		{http.StatusCreated, `{"status":{"allowed":false,"evaluationError":"webhook timed out"}}`},
		{http.StatusFound, ""}} {
		status, answer = failing.status, failing.answer
		if _, err := reviewer.Review(t.Context(), "t", attributes); err == nil {
			t.Errorf("%d %q: no error", failing.status, failing.answer)
		}
	}
	status, answer = http.StatusCreated, `{"status":{"allowed":false,"evaluationError":"role \"gone\" not found"}}`
	if _, err := reviewer.Review(t.Context(), "t", attributes); err == nil || !strings.Contains(err.Error(), "gone") {
		t.Fatalf("the authorizer's error is kept: %v", err)
	}
	for _, server := range []string{"http://a", "https://a#x", "https://a/path", "https://u@a"} {
		if _, err := NewAPIReviewer(server, ca); err == nil {
			t.Errorf("%s taken", server)
		}
	}
}

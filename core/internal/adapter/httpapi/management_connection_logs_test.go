package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/shared/flowlog"
)

const (
	testConnectionLogWorkspace = "01890f00-0000-7000-8000-000000000103"
	testConnectionLogNetwork   = "01890f00-0000-7000-8000-000000000203"
)

func TestParseConnectionLogPath(t *testing.T) {
	t.Parallel()
	credentials := "/api/v1/workspaces/" + testConnectionLogWorkspace + "/storage-credentials"
	item := credentials + "/01890f00-0000-7000-8000-000000000501"
	settings := "/api/v1/workspaces/" + testConnectionLogWorkspace + "/networks/" + testConnectionLogNetwork +
		"/connection-logs"
	for _, test := range []struct {
		method, target, operation, allow string
	}{
		{http.MethodGet, credentials, storageCredentialListOperation, "GET, POST"},
		{http.MethodPost, credentials, storageCredentialCreateOperation, "GET, POST"},
		{http.MethodPatch, item, storageCredentialUpdateOperation, "PATCH, DELETE"},
		{http.MethodDelete, item, storageCredentialDeleteOperation, "PATCH, DELETE"},
		{http.MethodGet, settings, connectionLogReadOperation, "GET, PUT"},
		{http.MethodPut, settings, connectionLogReplaceOperation, "GET, PUT"},
		{http.MethodGet, item, "", "PATCH, DELETE"},
		{http.MethodPost, settings, "", "GET, PUT"},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.target, nil)
		path, ok := parseConnectionLogPath(request)
		admitted := test.operation != ""
		if !ok || isConnectionLogOperation(request) != admitted || path.methods.header() != test.allow ||
			path.operation != test.operation {
			t.Errorf("%s %s: %+v matched %t", test.method, test.target, path, ok)
		}
	}
	for _, target := range []string{
		credentials + "/not-an-id", credentials + "?page=2", settings + "?x=1", settings + "/more",
		"/api/v1/workspaces/not-a-workspace/storage-credentials",
		"/api/v1/workspaces/" + testConnectionLogWorkspace + "/networks/x/connection-logs",
		"/api/v1/workspaces/" + testConnectionLogWorkspace + "/networks/" + testConnectionLogNetwork + "/other",
	} {
		if _, ok := parseConnectionLogPath(httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)); ok {
			t.Errorf("%s: matched", target)
		}
	}
	if !isConnectionLogRead(httptest.NewRequestWithContext(t.Context(), http.MethodGet, settings, nil)) ||
		!isConnectionLogSettingsWrite(httptest.NewRequestWithContext(t.Context(), http.MethodPut, settings, nil)) ||
		isConnectionLogSettingsWrite(httptest.NewRequestWithContext(t.Context(), http.MethodPut, item, nil)) {
		t.Fatal("reads or writes misclassified")
	}
}

func TestStorageCredentialRequest(t *testing.T) {
	t.Parallel()
	text := func(value string) *string { return &value }
	networks := []string{testConnectionLogNetwork}
	create := storageCredentialRequest{
		Name: text("Logs"), Provider: text(flowlog.ProviderS3),
		AccessKeyID: text("AKIAIOSFODNN7EXAMPLE"), SecretAccessKey: text("s"), Networks: &networks,
	}
	put, ok := create.put(true)
	if !ok || put.Secret == nil || put.Secret.Suffix() != "MPLE" || len(put.Networks) != 1 {
		t.Fatalf("put %+v %t", put, ok)
	}
	for name, body := range map[string]storageCredentialRequest{
		"create without secret": {Name: text("Logs"), Provider: text(flowlog.ProviderS3), Networks: &networks},
		"half a secret": {
			Name: text("Logs"), Provider: text(flowlog.ProviderS3), AccessKeyID: text("AKIAIOSFODNN7EXAMPLE"),
			Networks: &networks,
		},
		"no networks": {
			Name: text("Logs"), Provider: text(flowlog.ProviderS3), AccessKeyID: text("AKIAIOSFODNN7EXAMPLE"),
			SecretAccessKey: text("s"),
		},
		"bad network": {
			Name: text("Logs"), Provider: text(flowlog.ProviderS3), AccessKeyID: text("AKIAIOSFODNN7EXAMPLE"),
			SecretAccessKey: text("s"), Networks: &[]string{"x"},
		},
	} {
		if _, ok := body.put(true); ok {
			t.Errorf("%s: accepted", name)
		}
	}
	rename := storageCredentialRequest{Name: text("Logs"), Provider: text(flowlog.ProviderS3), Networks: &networks}
	if put, ok := rename.put(false); !ok || put.Secret != nil {
		t.Fatalf("a rename %+v %t", put, ok)
	}
}

func TestClassifyConnectionLogError(t *testing.T) {
	t.Parallel()
	for err, code := range map[error]string{
		connectionlog.ErrForbidden:   "permission_denied",
		connectionlog.ErrNotFound:    "storage_credential_not_found",
		connectionlog.ErrConflict:    "version_conflict",
		connectionlog.ErrInUse:       "storage_credential_in_use",
		connectionlog.ErrNotAllowed:  "connection_logs_not_allowed",
		connectionlog.ErrUnavailable: "temporarily_unavailable",
	} {
		if got := classifyConnectionLogError(err).Code; got != code {
			t.Errorf("%v: %s, want %s", err, got, code)
		}
	}
	if !strings.Contains(classifyConnectionLogError(connectionlog.ErrInvalid).Code, "invalid") {
		t.Error("invalid input")
	}
}

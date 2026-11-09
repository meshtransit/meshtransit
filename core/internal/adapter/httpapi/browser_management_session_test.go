package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// One Console start reads the Deployment capabilities and the first scope
// page under one admission: one authentication, one source and one Session
// budget, never two of each (TD-CON-48).
func TestBrowserManagementReadsSessionInOneAdmission(t *testing.T) {
	t.Parallel()
	browser, fixture := newBrowserManagementFixture(t)
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, browserManagementReadRequest(t, AccountSessionPath)); err != nil {
		t.Fatal(err)
	}
	var body sessionEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	expected := managementSessionFixture(t)
	scope := body.Data.ManagementScope
	validBody := body.Data.Capabilities.DeploymentProfile == "self_hosted" &&
		body.Data.Capabilities.CapabilityRevision == 7 &&
		scope.PrincipalID == expected.PrincipalID().String() &&
		scope.Workspace.ID == "01890f00-0000-7000-8000-000000000101" && len(scope.Networks) == 1 &&
		scope.Networks[0].ID == "01890f00-0000-7000-8000-000000000202" &&
		reflect.DeepEqual(scope.Networks[0].Permissions, []string{"policy.approve"}) &&
		body.CorrelationID != ""
	if response.Code != http.StatusOK || response.statusWrites != 1 || !validBody ||
		response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Set-Cookie") != "" ||
		response.Header().Get("Www-Authenticate") != "" ||
		fixture.auth != 1 || fixture.budgets != 2 || fixture.capabilityReads != 1 ||
		strings.Contains(response.Body.String(), expected.ID().String()) {
		t.Fatalf("session = %d/%+v/%s auth=%d budgets=%d capabilities=%d", response.Code, body,
			response.Body.String(), fixture.auth, fixture.budgets, fixture.capabilityReads)
	}
}

// The start read takes no query: the page size is the server's, and later
// pages come from the scope collection with the returned token.
func TestBrowserManagementSessionRefusesQueryAndOtherMethods(t *testing.T) {
	t.Parallel()
	browser, _ := newBrowserManagementFixture(t)
	withQuery := browserManagementReadRequest(t, AccountSessionPath+"?page_size=1")
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, withQuery); !errors.Is(err, ErrInvalidBrowserManagement) ||
		response.statusWrites != 0 || response.Body.Len() != 0 {
		t.Fatal("session read accepted a client-selected query", err)
	}
	withProof := browserManagementReadRequest(t, AccountSessionPath)
	withProof.Header.Set("X-MeshTransit-CSRF", "unexpected")
	response = &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, withProof); !errors.Is(err, ErrInvalidBrowserManagement) ||
		response.statusWrites != 0 {
		t.Fatal("session read accepted mutation transport", err)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		request := browserManagementReadRequest(t, AccountSessionPath)
		request.Method = method
		response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
		if err := browser.Handle(response, request); err == nil || response.statusWrites != 0 {
			t.Fatalf("%s %s was served", method, AccountSessionPath)
		}
	}
}

func TestLoginDispatcherPreservesSessionOwnership(t *testing.T) {
	t.Parallel()
	dispatcher, fixture, callback, management := dispatcherTestGraphWithManagement(t)
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := dispatcher.Handle(response, browserManagementReadRequest(t, AccountSessionPath)); err != nil {
		t.Fatal("session read did not reach its exact owner", err)
	}
	var body sessionEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil ||
		len(body.Data.ManagementScope.Networks) != 1 || body.Data.Capabilities.CapabilityRevision != 7 {
		t.Fatal("session read changed its bounded response", err)
	}
	if response.Code != http.StatusOK || response.statusWrites != 1 || management.auth != 1 ||
		management.budgets != 2 || management.capabilityReads != 1 || len(fixture.calls) != 0 ||
		callback.calls != 0 || response.Header().Get("Set-Cookie") != "" {
		t.Fatal("session read crossed owner boundaries")
	}
}

// Server-Timing is opt-in: it carries durations only, never a statement,
// and is absent unless the deployment turns it on.
func TestBrowserManagementServerTimingIsOptIn(t *testing.T) {
	t.Parallel()
	off, _ := newBrowserManagementFixture(t)
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := off.Handle(response, browserManagementReadRequest(t, AccountSessionPath)); err != nil {
		t.Fatal(err)
	}
	if response.Header().Get("Server-Timing") != "" {
		t.Fatal("Server-Timing sent while turned off")
	}
	options, _ := browserManagementTestOptions(t)
	options.ServerTiming = true
	on, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	response = &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := on.Handle(response, browserManagementReadRequest(t, AccountSessionPath)); err != nil {
		t.Fatal(err)
	}
	timing := response.Header().Get("Server-Timing")
	if response.Code != http.StatusOK ||
		!regexp.MustCompile(`^db;dur=[0-9]+\.[0-9], redis;dur=[0-9]+\.[0-9], app;dur=[0-9]+\.[0-9]$`).MatchString(timing) {
		t.Fatalf("Server-Timing = %q (status %d)", timing, response.Code)
	}
}

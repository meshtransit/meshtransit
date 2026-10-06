package httpapi

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network/provisioning"
	"github.com/meshtransit/meshtransit/internal/workspace"
	"github.com/meshtransit/meshtransit/internal/workspace/creation"
	"github.com/meshtransit/meshtransit/internal/workspace/selection"
)

// The Console reads members and switchable Workspaces with a cookie-only GET
// through the private browser profile, like other safe reads.
func TestBrowserCookieReadsReachWorkspaceDirectories(t *testing.T) {
	t.Parallel()
	current, _ := workspace.ParseID(managementWorkspaceID())
	code, _ := identity.ParseDisplayCode("004218650921")
	for _, path := range []string{
		SessionWorkspacesPath,
		"/api/v1/workspaces/" + managementWorkspaceID() + "/members",
		shareTargetTestPath("798657066103"),
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			options, _ := browserManagementTestOptions(t)
			options.Management.sessionWorkspaces = &sessionWorkspaceSelectorStub{candidates: []selection.Candidate{
				{WorkspaceID: current, DisplayName: "Engineering", DisplayCode: code, Current: true}}}
			options.Management.workspaceRoles = &workspaceRoleManagerStub{}
			options.Management.shareTargets = &shareTargetResolverStub{}
			browser, err := NewBrowserManagement(options)
			if err != nil {
				t.Fatal(err)
			}
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			if err := browser.Handle(response, browserManagementReadRequest(t, path)); err != nil {
				t.Fatalf("Handle() error = %v", err)
			}
			if response.Code != http.StatusOK || response.Header().Get("Set-Cookie") != "" {
				t.Fatalf("status %d; %s", response.Code, response.Body)
			}
		})
	}
}

// Switching is a cookie mutation: it needs a current proof bound to the cookie.
func TestBrowserSessionWorkspaceSwitchRequiresProof(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"valid", "missing proof", "foreign origin"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			options, _ := browserManagementTestOptions(t)
			stub := &sessionWorkspaceSelectorStub{}
			options.Management.sessionWorkspaces = stub
			browser, err := NewBrowserManagement(options)
			if err != nil {
				t.Fatal(err)
			}
			proof := preparedBrowserProof(t, browser)
			request := browserManagementRequest(t, SessionWorkspacePath,
				`{"workspace_id":"01890f00-0000-7000-8000-000000000102"}`)
			request.Header.Del("If-Match")
			request.Header.Del("Idempotency-Key")
			request.Header.Set("X-MeshTransit-CSRF", proof)
			switch mode {
			case "missing proof":
				request.Header.Del("X-MeshTransit-CSRF")
			case "foreign origin":
				request.Header.Set("Origin", "https://foreign.example.test")
			}
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			err = browser.Handle(response, request)
			if mode == "valid" {
				if err != nil || response.Code != http.StatusOK || stub.switches != 1 {
					t.Fatalf("switch = %d, %v; %s", response.Code, err, response.Body)
				}
				return
			}
			if stub.switches != 0 || (err == nil && response.Code < 400) {
				t.Fatalf("%s reached the switch: %d, %v", mode, response.Code, err)
			}
		})
	}
}

// The Console's other private mutations reach their handlers through the
// browser profile with a current proof.
func TestBrowserConsoleMutationsReachHandlers(t *testing.T) {
	t.Parallel()
	code, _ := identity.ParseDisplayCode("004218650921")
	for _, test := range []struct {
		name, path, body string
		status           int
	}{
		{"create Workspace", WorkspaceCollectionPath,
			`{"workspace_id":"01890f00-0000-7000-8000-000000000105","display_name":"Finance"}`, http.StatusCreated},
		{"create Network", "/api/v1/workspaces/" + managementWorkspaceID() + "/networks",
			`{"network_id":"01990f00-0000-7000-8000-000000000d01","display_name":"Office","ipv4_prefix":"100.64.10.0/24"}`,
			http.StatusCreated},
		{"assign role", "/api/v1/workspaces/" + managementWorkspaceID() + "/role-assignments",
			`{"assignment_id":"` + testAssignmentID + `","principal_id":"` + testPrincipalID + `","role":"auditor"}`,
			http.StatusCreated},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options, _ := browserManagementTestOptions(t)
			calls := 0
			options.Management.workspaceCreations = workspaceCreatorFunc(func(_ context.Context, command creation.Command) (creation.Result, error) {
				calls++
				return creation.Result{WorkspaceID: command.WorkspaceID, DisplayName: command.DisplayName, DisplayCode: code,
					Version: 1, CreatedAt: time.Unix(1, 0).UTC()}, nil
			})
			options.Management.networkCreations = networkCreatorFunc(func(_ context.Context, command provisioning.Command) (provisioning.Result, error) {
				calls++
				return provisioning.Result{NetworkID: command.NetworkID, DisplayCode: code, IPv4Prefix: command.IPv4Prefix,
					IPv6Prefix: netip.MustParsePrefix("fd42:42:42::/64"), Version: 1, CreatedAt: time.Unix(1, 0).UTC()}, nil
			})
			roles := &workspaceRoleManagerStub{}
			options.Management.workspaceRoles = roles
			browser, err := NewBrowserManagement(options)
			if err != nil {
				t.Fatal(err)
			}
			request := browserManagementRequest(t, test.path, test.body)
			request.Header.Del("If-Match")
			request.Header.Del("Idempotency-Key")
			request.Header.Set("X-MeshTransit-CSRF", preparedBrowserProof(t, browser))
			response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
			if err := browser.Handle(response, request); err != nil {
				t.Fatalf("Handle() error = %v", err)
			}
			if response.Code != test.status || calls+roles.calls != 1 {
				t.Fatalf("status %d, calls %d; %s", response.Code, calls+roles.calls, response.Body)
			}
		})
	}
}

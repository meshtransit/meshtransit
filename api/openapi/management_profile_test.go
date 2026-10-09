package openapi_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"meshtransit.net/api/openapi"
)

func TestManagementDocumentRejectsUnknownProfiles(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", "bearer", "console", "console-cookie-csrf-private-v1\n", strings.Repeat("x", 4096)} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			body, err := openapi.ManagementDocument(openapi.ManagementProfile(name))
			if body != nil || !errors.Is(err, openapi.ErrInvalidManagementProfile) {
				t.Fatal("unknown profile selected an authentication fallback")
			}
			if err.Error() != "openapi: invalid management profile" {
				t.Fatal("profile diagnostic disclosed caller input")
			}
		})
	}
}

func TestManagementDocumentPreservesBearerBytesAndOwnership(t *testing.T) {
	t.Parallel()
	expected, err := os.ReadFile("management_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		body, err := openapi.ManagementDocument(openapi.ManagementProfileBearerV1)
		if err != nil || !bytes.Equal(body, expected) {
			t.Fatal("Bearer document changed", err)
		}
		clear(body)
	}
}

func TestManagementDocumentConsoleUsesOneResourceContract(t *testing.T) {
	t.Parallel()
	baseBytes, err := os.ReadFile("management_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	body, err := openapi.ManagementDocument(openapi.ManagementProfileConsoleCookiePrivateV1)
	if err != nil || len(body) > 1<<20 {
		t.Fatal("private document did not compose within its bound", err)
	}
	base, console := profileObject(t, baseBytes), profileObject(t, body)
	validIdentity := console["openapi"] == "3.1.0" &&
		console["x-meshtransit-auth-profile"] == "console-cookie-csrf-private-v1"
	privateSelection := console["x-meshtransit-runtime-status"] == "private-source-only" && console["security"] == nil
	if !validIdentity || !privateSelection {
		t.Fatal("private source profile inherited or enabled authentication")
	}
	servers := profileArray(t, console, "servers")
	if len(servers) != 1 || !reflect.DeepEqual(servers[0], map[string]any{"url": "https://console.example.test"}) {
		t.Fatal("private document retained deployment topology")
	}
	basePaths, paths := profileMap(t, base, "paths"), profileMap(t, console, "paths")
	// The private document adds only Console session routes, the two
	// receiving-Network alias range routes, the Workspace audit history and
	// export, and the four Workspace guardrail routes.
	if len(basePaths) != 31 || len(paths) != 69 {
		t.Fatal("private profile introduced another product resource API")
	}
	for path, raw := range paths {
		if !strings.Contains(path, "/resources") && !strings.Contains(path, "/share-offers") && !strings.Contains(path, "/trust-contracts") {
			continue
		}
		item := raw.(map[string]any)
		for method := range item {
			operation := profileMap(t, item, method)
			baseOperation := profileMap(t, profileMap(t, basePaths, path), method)
			security := map[string]any{"accountSessionCookie": []any{}}
			additional := 2
			if method == "post" {
				security["sessionCSRF"] = []any{}
				additional = 3
			}
			if !reflect.DeepEqual(operation["security"], []any{security}) {
				t.Fatal("Resource/sharing profile gained a credential fallback")
			}
			for key, value := range baseOperation {
				if key != "security" && key != "parameters" && !reflect.DeepEqual(operation[key], value) {
					t.Fatal("Resource/sharing product contract drift", path, key)
				}
			}
			oldParameters := profileArray(t, baseOperation, "parameters")
			parameters := profileArray(t, operation, "parameters")
			if len(parameters) != len(oldParameters)+additional || !reflect.DeepEqual(parameters[:len(oldParameters)], oldParameters) {
				t.Fatal("Resource/sharing scope/precondition/idempotency changed")
			}
		}
	}
	for _, path := range []string{
		"/api/v1/workspaces/{workspace_id}/networks/{network_id}/devices/{device_id}/actions/revoke",
		"/api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/actions/publish",
		"/api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/actions/simulate",
		"/api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/approval-requests",
		"/api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/approval-requests/{approval_request_id}/actions/approve",
		"/api/v1/workspaces/{workspace_id}/networks/{network_id}/access-graph/actions/explain",
	} {
		baseOperation := profileMap(t, profileMap(t, basePaths, path), "post")
		item := profileMap(t, paths, path)
		expectedMethods := 1
		if path == "/api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/approval-requests" {
			expectedMethods = 2
		}
		if len(item) != expectedMethods {
			t.Fatal("resource profile added a method or inherited parameters")
		}
		operation := profileMap(t, item, "post")
		expectedSecurity := []any{map[string]any{"accountSessionCookie": []any{}, "sessionCSRF": []any{}}}
		if !reflect.DeepEqual(operation["security"], expectedSecurity) {
			t.Fatal("mutation does not require cookie AND proof, or allows Bearer/anonymous OR")
		}
		for key, expected := range baseOperation {
			resourceField := key != "security" && key != "parameters"
			if resourceField && !reflect.DeepEqual(operation[key], expected) {
				t.Fatalf("single resource contract drifted at %s", key)
			}
		}
		baseParameters := profileArray(t, baseOperation, "parameters")
		parameters := profileArray(t, operation, "parameters")
		if len(parameters) != len(baseParameters)+3 ||
			!reflect.DeepEqual(parameters[:len(baseParameters)], baseParameters) {
			t.Fatal("resource scope/ETag/idempotency parameters changed")
		}
		for index, name := range []string{"ConsoleOrigin", "ConsoleSessionChannel", "ConsoleSessionProof"} {
			if !reflect.DeepEqual(parameters[len(baseParameters)+index], map[string]any{
				"$ref": "#/components/parameters/" + name,
			}) {
				t.Fatal("mutation omitted a required browser parameter")
			}
		}
	}
	for _, path := range []string{
		"/api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/approval-requests",
		"/api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/approval-requests/{approval_request_id}",
	} {
		baseOperation := profileMap(t, profileMap(t, basePaths, path), "get")
		operation := profileMap(t, profileMap(t, paths, path), "get")
		expectedSecurity := []any{map[string]any{"accountSessionCookie": []any{}}}
		if !reflect.DeepEqual(operation["security"], expectedSecurity) {
			t.Fatal("approval catalog read gained mutation proof or a Bearer/anonymous fallback")
		}
		for key, expected := range baseOperation {
			resourceField := key != "security" && key != "parameters"
			if resourceField && !reflect.DeepEqual(operation[key], expected) {
				t.Fatalf("approval catalog contract drifted at %s", key)
			}
		}
		baseParameters := profileArray(t, baseOperation, "parameters")
		parameters := profileArray(t, operation, "parameters")
		if len(parameters) != len(baseParameters)+2 ||
			!reflect.DeepEqual(parameters[:len(baseParameters)], baseParameters) {
			t.Fatal("approval catalog scope/filter parameters changed")
		}
		for index, name := range []string{"ConsoleOrigin", "ConsoleSessionChannel"} {
			if !reflect.DeepEqual(parameters[len(baseParameters)+index], map[string]any{
				"$ref": "#/components/parameters/" + name,
			}) {
				t.Fatal("approval catalog read omitted required browser intent")
			}
		}
	}
	baseComponents, components := profileMap(t, base, "components"), profileMap(t, console, "components")
	for _, section := range []string{"schemas", "parameters", "headers", "responses"} {
		for name, expected := range profileMap(t, baseComponents, section) {
			if !reflect.DeepEqual(profileMap(t, components, section)[name], expected) {
				t.Fatalf("shared resource component changed: %s/%s", section, name)
			}
		}
	}
	schemes := profileMap(t, components, "securitySchemes")
	if len(schemes) != 2 || schemes["accountSessionBearer"] != nil {
		t.Fatal("private Console retained Bearer transport")
	}
	for _, test := range []struct{ name, location, parameter string }{
		{name: "accountSessionCookie", location: "cookie", parameter: "__Host-mt_session"},
		{name: "sessionCSRF", location: "header", parameter: "X-MeshTransit-CSRF"},
	} {
		scheme := profileMap(t, schemes, test.name)
		if scheme["type"] != "apiKey" || scheme["in"] != test.location || scheme["name"] != test.parameter {
			t.Fatal("browser security scheme changed transport")
		}
	}
	parameters := profileMap(t, components, "parameters")
	for _, name := range []string{"ConsoleOrigin", "ConsoleSessionChannel", "ConsoleSessionProof"} {
		parameter := profileMap(t, parameters, name)
		if parameter["in"] != "header" || parameter["required"] != true {
			t.Fatal("browser intent became an optional or URL parameter")
		}
	}
	profileReferences(t, console, console)
}

func TestManagementDocumentConsoleScopesAreReadOnlyNavigationEvidence(t *testing.T) {
	t.Parallel()
	body, err := openapi.ManagementDocument(openapi.ManagementProfileConsoleCookiePrivateV1)
	if err != nil {
		t.Fatal(err)
	}
	document := profileObject(t, body)
	item := profileMap(t, profileMap(t, document, "paths"), "/auth/v1/session/management-scopes")
	if len(item) != 1 {
		t.Fatal("management-scope projection exposes another method")
	}
	operation := profileMap(t, item, "get")
	expectedSecurity := []any{map[string]any{"accountSessionCookie": []any{}}}
	if operation["operationId"] != "listConsoleManagementScopes" ||
		!reflect.DeepEqual(operation["security"], expectedSecurity) || operation["requestBody"] != nil {
		t.Fatal("management-scope projection gained mutation proof, body or authentication fallback")
	}
	parameters := profileArray(t, operation, "parameters")
	if len(parameters) != 4 ||
		!reflect.DeepEqual(parameters[0], map[string]any{"$ref": "#/components/parameters/ConsoleOrigin"}) ||
		!reflect.DeepEqual(parameters[1], map[string]any{"$ref": "#/components/parameters/ConsoleSessionChannel"}) {
		t.Fatal("management-scope projection lost exact browser channel or bounded pagination")
	}
	pageSize := profileMap(t, parameters[2].(map[string]any), "schema")
	pageToken := profileMap(t, parameters[3].(map[string]any), "schema")
	if pageSize["minimum"] != float64(1) || pageSize["maximum"] != float64(100) ||
		pageToken["maxLength"] != float64(512) {
		t.Fatal("management-scope pagination is not bounded")
	}
	responses := profileMap(t, operation, "responses")
	response := profileMap(t, responses, "200")
	if profileMap(t, profileMap(t, response, "headers"), "Cache-Control")["schema"] == nil {
		t.Fatal("management-scope projection lost no-store response")
	}
	schema := profileMap(t, profileMap(t, document, "components"), "schemas")
	projection := profileMap(t, schema, "ConsoleManagementScopePage")
	if projection["additionalProperties"] != false {
		t.Fatal("management-scope response became open-ended")
	}
	profileReferences(t, document, operation)
}

func TestManagementDocumentConsoleCapabilitiesAreAuthenticatedNavigationEvidence(t *testing.T) {
	t.Parallel()
	body, err := openapi.ManagementDocument(openapi.ManagementProfileConsoleCookiePrivateV1)
	if err != nil {
		t.Fatal(err)
	}
	document := profileObject(t, body)
	item := profileMap(t, profileMap(t, document, "paths"), "/v1/system/capabilities")
	if len(item) != 1 {
		t.Fatal("Deployment capability projection exposes another method")
	}
	operation := profileMap(t, item, "get")
	expectedSecurity := []any{map[string]any{"accountSessionCookie": []any{}}}
	if operation["operationId"] != "getConsoleDeploymentCapabilities" ||
		!reflect.DeepEqual(operation["security"], expectedSecurity) || operation["requestBody"] != nil {
		t.Fatal("Deployment capability projection gained mutation proof, body or authentication fallback")
	}
	parameters := profileArray(t, operation, "parameters")
	if len(parameters) != 2 ||
		!reflect.DeepEqual(parameters[0], map[string]any{"$ref": "#/components/parameters/ConsoleOrigin"}) ||
		!reflect.DeepEqual(parameters[1], map[string]any{"$ref": "#/components/parameters/ConsoleSessionChannel"}) {
		t.Fatal("Deployment capability projection lost exact browser intent")
	}
	schemas := profileMap(t, profileMap(t, document, "components"), "schemas")
	projection := profileMap(t, schemas, "ConsoleDeploymentCapabilities")
	if projection["additionalProperties"] != false {
		t.Fatal("Deployment capability projection accepts unknown fields")
	}
	properties := profileMap(t, projection, "properties")
	if len(properties) != 9 || profileMap(t, properties, "max_active_workspaces")["maximum"] != float64(1000000) ||
		!reflect.DeepEqual(profileMap(t, properties, "workspace_mode")["enum"], []any{"single", "multi"}) ||
		!reflect.DeepEqual(profileMap(t, properties, "entitlement_state")["enum"],
			[]any{"none", "active", "grace", "expired"}) ||
		len(profileArray(t, projection, "required")) != 9 {
		t.Fatal("Deployment capability projection lost its bounded entitlement-derived shape")
	}
}

func TestManagementDocumentConsoleLogoutIsDurableAndCookieScoped(t *testing.T) {
	t.Parallel()
	body, err := openapi.ManagementDocument(openapi.ManagementProfileConsoleCookiePrivateV1)
	if err != nil {
		t.Fatal(err)
	}
	document := profileObject(t, body)
	item := profileMap(t, profileMap(t, document, "paths"), "/auth/v1/session/logout")
	if len(item) != 1 {
		t.Fatal("logout exposes another method")
	}
	operation := profileMap(t, item, "post")
	expectedSecurity := []any{map[string]any{"accountSessionCookie": []any{}, "sessionCSRF": []any{}}}
	if operation["operationId"] != "logoutConsoleSession" ||
		!reflect.DeepEqual(operation["security"], expectedSecurity) ||
		len(profileArray(t, operation, "parameters")) != 3 {
		t.Fatal("logout lost exact cookie and proof authentication")
	}
	request := profileMap(t, operation, "requestBody")
	schema := profileMap(t, profileMap(t, profileMap(t, request, "content"), "application/json"), "schema")
	if request["required"] != true || request["x-meshtransit-max-bytes"] != float64(4096) ||
		schema["type"] != "object" || schema["additionalProperties"] != false || schema["maxProperties"] != float64(0) {
		t.Fatal("logout body is not the bounded literal empty object")
	}
	responses := profileMap(t, operation, "responses")
	if len(responses) != 2 || profileMap(t, responses, "204")["content"] != nil {
		t.Fatal("logout success is not an empty 204")
	}
	headers := profileMap(t, profileMap(t, responses, "204"), "headers")
	setCookie := profileMap(t, profileMap(t, headers, "Set-Cookie"), "schema")
	expectedCookie := "__Host-mt_session=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT; Max-Age=0; HttpOnly; Secure; SameSite=Lax"
	if setCookie["const"] != expectedCookie || strings.Contains(expectedCookie, "Domain=") {
		t.Fatal("logout changes more than the host-only Core Session cookie")
	}
	failure := profileMap(t, responses, "default")
	if failure["content"] != nil || failure["headers"] != nil {
		t.Fatal("logout contract invented failure credentials or content")
	}
	profileReferences(t, document, operation)
}

func TestManagementDocumentConsolePreparationIsNoGrant(t *testing.T) {
	t.Parallel()
	body, err := openapi.ManagementDocument(openapi.ManagementProfileConsoleCookiePrivateV1)
	if err != nil {
		t.Fatal(err)
	}
	document := profileObject(t, body)
	item := profileMap(t, profileMap(t, document, "paths"), "/auth/v1/session/prepare")
	if len(item) != 1 {
		t.Fatal("prepare exposes authority through another method")
	}
	operation := profileMap(t, item, "post")
	if !reflect.DeepEqual(operation["security"], []any{map[string]any{"accountSessionCookie": []any{}}}) {
		t.Fatal("preparation requires nonexistent proof or an authentication fallback")
	}
	if len(profileArray(t, operation, "parameters")) != 2 {
		t.Fatal("prepare transport omitted Origin/channel or requires existing proof")
	}
	request := profileMap(t, operation, "requestBody")
	schema := profileMap(t, profileMap(t, profileMap(t, request, "content"), "application/json"), "schema")
	validBodyBound := request["required"] == true && request["x-meshtransit-max-bytes"] == float64(4096)
	validObject := schema["type"] == "object" && schema["additionalProperties"] == false
	if !validBodyBound || !validObject || schema["maxProperties"] != float64(0) {
		t.Fatal("prepare no longer describes the bounded literal empty object")
	}
	responses := profileMap(t, operation, "responses")
	failure := profileMap(t, responses, "default")
	untouchedFailure := failure["content"] == nil && failure["headers"] == nil
	if len(responses) != 2 || !untouchedFailure {
		t.Fatal("private pre-release failure invented HTTP output or credentials")
	}
	response := profileMap(t, responses, "200")
	if profileMap(t, response, "headers")["Set-Cookie"] != nil {
		t.Fatal("prepare document renews a Session")
	}
	components := profileMap(t, document, "components")
	prepared := profileMap(t, profileMap(t, components, "schemas"), "ConsoleCSRFPrepared")
	properties := profileMap(t, prepared, "properties")
	exactFields := prepared["additionalProperties"] == false && len(properties) == 2
	requiredFields := properties["csrf_token"] != nil && properties["expires_at"] != nil
	if !exactFields || !requiredFields || len(profileArray(t, prepared, "required")) != 2 {
		t.Fatal("proof response exposes authority/provider data or omits expiry")
	}
	proof := profileMap(t, profileMap(t, components, "schemas"), "ConsoleSessionProof")
	if proof["type"] != "string" || proof["maxLength"] != float64(256) {
		t.Fatal("proof contract lost its bounded envelope")
	}
	again, err := openapi.ManagementDocument(openapi.ManagementProfileConsoleCookiePrivateV1)
	if err != nil || !bytes.Equal(body, again) {
		t.Fatal("private rendering is not deterministic", err)
	}
	clear(body)
	third, err := openapi.ManagementDocument(openapi.ManagementProfileConsoleCookiePrivateV1)
	if err != nil || !bytes.Equal(third, again) {
		t.Fatal("caller mutation escaped private output ownership", err)
	}
}

func FuzzManagementDocumentProfile(f *testing.F) {
	f.Add("")
	f.Add("account-session-bearer-v1")
	f.Add("console-cookie-csrf-private-v1")
	f.Add("console-cookie-csrf-private-v1\x00")
	f.Fuzz(func(t *testing.T, input string) {
		body, err := openapi.ManagementDocument(openapi.ManagementProfile(input))
		known := input == "account-session-bearer-v1" || input == "console-cookie-csrf-private-v1"
		if !known {
			if body != nil || !errors.Is(err, openapi.ErrInvalidManagementProfile) {
				t.Fatal("arbitrary profile enabled a transport")
			}
			return
		}
		completeDocument := len(body) <= 1<<20 && json.Valid(body)
		if err != nil || !completeDocument {
			t.Fatal("known profile returned an incomplete or unbounded document", err)
		}
	})
}

func profileObject(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil || value == nil {
		t.Fatal("invalid contract object", err)
	}
	return value
}

func profileMap(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key].(map[string]any)
	if !ok || value == nil {
		t.Fatalf("missing contract object %s", key)
	}
	return value
}

func profileArray(t *testing.T, object map[string]any, key string) []any {
	t.Helper()
	value, ok := object[key].([]any)
	if !ok || value == nil {
		t.Fatalf("missing contract array %s", key)
	}
	return value
}

func profileReferences(t *testing.T, root map[string]any, value any) {
	t.Helper()
	switch node := value.(type) {
	case map[string]any:
		if reference, ok := node["$ref"].(string); ok {
			if !strings.HasPrefix(reference, "#/") {
				t.Fatal("contract requires an external runtime resolver")
			}
			current := root
			for _, part := range strings.Split(reference[2:], "/") {
				name := strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
				current = profileMap(t, current, name)
			}
		}
		for _, child := range node {
			profileReferences(t, root, child)
		}
	case []any:
		for _, child := range node {
			profileReferences(t, root, child)
		}
	}
}

func TestShareAcceptanceContractRequiresOnlyTheImportedName(t *testing.T) {
	t.Parallel()
	for _, profile := range []openapi.ManagementProfile{
		openapi.ManagementProfileBearerV1,
		openapi.ManagementProfileConsoleCookiePrivateV1,
	} {
		document, err := openapi.ManagementDocument(profile)
		if err != nil {
			t.Fatal(err)
		}
		schemas := profileMap(t, profileMap(t, profileObject(t, document), "components"), "schemas")
		accept := profileMap(t, schemas, "AcceptShareOfferRequest")
		parts := profileArray(t, accept, "allOf")
		if len(parts) != 2 || !reflect.DeepEqual(parts[0], map[string]any{
			"$ref": "#/components/schemas/DecideShareOfferRequest",
		}) {
			t.Fatal("acceptance lost the shared scope, token and reason contract")
		}
		names, ok := parts[1].(map[string]any)
		// The access name is derived from the provider label, so only the
		// consumer-local imported name stays required.
		if !ok || !reflect.DeepEqual(names["required"], []any{"imported_display_name"}) {
			t.Fatal("acceptance must require only the imported display name")
		}
	}
}

func TestManagementDocumentConsoleWorkspaceRolesAreCookieScoped(t *testing.T) {
	t.Parallel()
	body, err := openapi.ManagementDocument(openapi.ManagementProfileConsoleCookiePrivateV1)
	if err != nil {
		t.Fatal(err)
	}
	paths := profileMap(t, profileObject(t, body), "paths")
	for _, test := range []struct{ path, method, operationID string }{
		{"/api/v1/workspaces", "post", "createWorkspace"},
		{"/api/v1/workspaces/{workspace_id}/networks", "post", "createNetwork"},
		{"/auth/v1/session/workspaces", "get", "listSessionWorkspaces"},
		{"/auth/v1/session/workspace", "post", "switchSessionWorkspace"},
		{"/api/v1/workspaces/{workspace_id}/networks/{network_id}/share-targets/{network_display_code}", "get", "resolveShareTarget"},
		{"/api/v1/workspaces/{workspace_id}/members", "get", "listWorkspaceMembers"},
		{"/api/v1/workspaces/{workspace_id}/role-assignments", "post", "assignWorkspaceRole"},
		{"/api/v1/workspaces/{workspace_id}/role-assignments/{assignment_id}/actions/revoke", "post", "revokeWorkspaceRole"},
	} {
		item := profileMap(t, paths, test.path)
		if len(item) != 1 {
			t.Fatal("role path exposes extra methods", test.path)
		}
		operation := profileMap(t, item, test.method)
		security := map[string]any{"accountSessionCookie": []any{}}
		if test.method == "post" {
			security["sessionCSRF"] = []any{}
		}
		if operation["operationId"] != test.operationID || !reflect.DeepEqual(operation["security"], []any{security}) {
			t.Fatal("role operation identity or credential drift", test.path)
		}
	}
}

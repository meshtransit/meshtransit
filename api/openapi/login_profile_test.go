package openapi_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/api/openapi"
)

func TestLoginDocumentRejectsProfileAndRoutingFallbacks(t *testing.T) {
	t.Parallel()
	for _, profile := range []openapi.ManagementProfile{"", "unknown", openapi.ManagementProfileBearerV1} {
		t.Run("profile "+string(profile), func(t *testing.T) {
			t.Parallel()
			body, err := openapi.LoginDocument(profile, "/auth/callback")
			if body != nil || !errors.Is(err, openapi.ErrInvalidLoginProfile) {
				t.Fatal("unsupported login profile released a document")
			}
		})
	}
	for _, path := range []string{
		"", "/", "/auth", "/auth/", "/api/v1/callback", "/machine/register", "/key", "/ts2021",
		"https://console.example.test/auth/callback", "//auth/callback", "/auth/callback/", "/auth//callback",
		"/auth/../callback", "/auth/./callback", "/auth/callback?code=private", "/auth/callback#state",
		"/auth/call%62ack", "/auth/call\\back", "/auth/é", "/auth/" + strings.Repeat("x", 251),
		"/auth/v1/login/prepare", "/auth/v1/login/start", "/auth/v1/login/continue",
		"/auth/v1/login/continue/prepare", "/auth/v1/session/prepare",
	} {
		t.Run("path "+path, func(t *testing.T) {
			t.Parallel()
			body, err := openapi.LoginDocument(openapi.ManagementProfileConsoleCookiePrivateV1, path)
			if body != nil || !errors.Is(err, openapi.ErrInvalidLoginProfile) {
				t.Fatal("alternate/overlapping callback released a document")
			}
			if err.Error() != "openapi: invalid login profile" {
				t.Fatal("callback diagnostic disclosed input")
			}
		})
	}
}

func TestLoginDocumentDescribesExactPrivateMethodsAndIntent(t *testing.T) {
	t.Parallel()
	callback := "/auth/custom/callback"
	body, err := openapi.LoginDocument(openapi.ManagementProfileConsoleCookiePrivateV1, callback)
	if err != nil || len(body) > 128<<10 {
		t.Fatal("private login document unavailable/unbounded", err)
	}
	document := profileObject(t, body)
	if document["openapi"] != "3.1.0" || document["security"] != nil ||
		document["x-meshtransit-runtime-status"] != "private-source-only" ||
		document["x-meshtransit-auth-profile"] != "console-cookie-csrf-private-v1" {
		t.Fatal("document introduced default or inherited authentication")
	}
	if !reflect.DeepEqual(profileArray(t, document, "servers"), []any{
		map[string]any{"url": "https://console.example.test"},
	}) {
		t.Fatal("document introduced deployment/provider topology")
	}
	paths := profileMap(t, document, "paths")
	if len(paths) != 5 || paths["/auth/v1/login/callback"] != nil {
		t.Fatal("callback remapping left an alias or added another route")
	}
	for _, test := range []struct {
		path, method, id string
		security         []any
	}{
		{path: "/auth/v1/login/prepare", method: "post", id: "prepareBrowserLogin", security: []any{}},
		{path: "/auth/v1/login/start", method: "post", id: "startBrowserLogin", security: []any{
			map[string]any{"loginInitiationCookie": []any{}, "loginIntentProof": []any{}},
		}},
		{path: callback, method: "get", id: "captureBrowserLoginCallback", security: []any{
			map[string]any{"preAuthCookie": []any{}},
		}},
		{path: "/auth/v1/login/continue", method: "get", id: "presentBrowserLoginContinuation", security: []any{}},
		{path: "/auth/v1/login/continue", method: "head", id: "headBrowserLoginContinuation", security: []any{}},
		{path: "/auth/v1/login/continue/prepare", method: "post", id: "prepareBrowserLoginContinuation", security: []any{
			map[string]any{"preAuthCookie": []any{}, "capturedCallbackCookie": []any{}},
		}},
		{path: "/auth/v1/login/continue", method: "post", id: "completeBrowserLogin", security: []any{
			map[string]any{"preAuthCookie": []any{}, "capturedCallbackCookie": []any{}, "continuationIntentProof": []any{}},
		}},
	} {
		item := profileMap(t, paths, test.path)
		expectedMethods := 1
		if test.path == "/auth/v1/login/continue" {
			expectedMethods = 3
		}
		operation := profileMap(t, item, test.method)
		if len(item) != expectedMethods || operation["operationId"] != test.id ||
			!reflect.DeepEqual(operation["security"], test.security) {
			t.Fatal("private method/operation/AND intent requirements drifted")
		}
		responses := profileMap(t, operation, "responses")
		if len(responses) == 0 || responses["default"] == nil {
			t.Fatal("private failure/partial-delivery contract missing")
		}
		if test.method == "post" {
			request := profileMap(t, operation, "requestBody")
			schema := profileMap(t, profileMap(t, profileMap(t, request, "content"), "application/json"), "schema")
			if request["required"] != true || request["x-meshtransit-max-bytes"] != float64(32) ||
				schema["type"] != "object" || schema["maxProperties"] != float64(0) || schema["additionalProperties"] != false {
				t.Fatal("login POST accepts selectors or an unbounded body")
			}
			parameters := profileArray(t, operation, "parameters")
			if len(parameters) != 2 || !reflect.DeepEqual(parameters, []any{
				map[string]any{"$ref": "#/components/parameters/LoginOrigin"},
				map[string]any{"$ref": "#/components/parameters/LoginChannel"},
			}) {
				t.Fatal("POST omits exact Origin/channel intent")
			}
		}
	}
	profileReferences(t, document, document)
	components := profileMap(t, document, "components")
	schemes := profileMap(t, components, "securitySchemes")
	if len(schemes) != 5 {
		t.Fatal("unreviewed provider/Bearer credential scheme")
	}
	for _, test := range []struct{ key, location, name string }{
		{key: "loginInitiationCookie", location: "cookie", name: "__Host-mt_login_init"},
		{key: "preAuthCookie", location: "cookie", name: "__Host-mt_pre_auth"},
		{key: "capturedCallbackCookie", location: "cookie", name: "__Host-mt_login_callback"},
		{key: "loginIntentProof", location: "header", name: "X-MeshTransit-CSRF"},
		{key: "continuationIntentProof", location: "header", name: "X-MeshTransit-CSRF"},
	} {
		scheme := profileMap(t, schemes, test.key)
		if scheme["type"] != "apiKey" || scheme["in"] != test.location || scheme["name"] != test.name {
			t.Fatal("intent credential transport changed")
		}
	}
	for name, fields := range map[string][]string{
		"LoginIntentPrepared":       {"csrf_token", "expires_in"},
		"LoginContinuationPrepared": {"csrf_token", "expires_in"},
		"LoginStarted":              {"authorization_url"},
		"LoginCompleted":            {"return_path"},
	} {
		schema := profileMap(t, profileMap(t, components, "schemas"), name)
		properties := profileMap(t, schema, "properties")
		if schema["additionalProperties"] != false || len(properties) != len(fields) ||
			len(profileArray(t, schema, "required")) != len(fields) {
			t.Fatal("successful JSON exposes credential/authority fields")
		}
		for _, field := range fields {
			if properties[field] == nil {
				t.Fatal("successful JSON omits its exact field")
			}
		}
	}
	proof := profileMap(t, profileMap(t, components, "schemas"), "LoginIntentProof")
	pattern, ok := proof["pattern"].(string)
	if !ok {
		t.Fatal("intent encoding contract missing")
	}
	matcher, err := regexp.Compile(pattern)
	if err != nil || !matcher.MatchString("AQAB_ab-12") || matcher.MatchString("AQAB=private") {
		t.Fatal("intent shape accepts padding or rejects canonical base64url", err)
	}
}

func TestLoginDocumentPreservesTransportAndSuccessBounds(t *testing.T) {
	t.Parallel()
	body, err := openapi.LoginDocument(openapi.ManagementProfileConsoleCookiePrivateV1, "/auth/callback")
	if err != nil {
		t.Fatal(err)
	}
	document := profileObject(t, body)
	components := profileMap(t, document, "components")
	origin := profileMap(t, profileMap(t, profileMap(t, components, "parameters"), "LoginOrigin"), "schema")
	if origin["maxLength"] != float64(255) {
		t.Fatal("document disagrees with the existing origin guard")
	}
	schemas := profileMap(t, components, "schemas")
	for _, test := range []struct {
		schema, field, bound string
		maximum              float64
	}{
		{schema: "LoginIntentPrepared", field: "expires_in", bound: "maximum", maximum: 300},
		{schema: "LoginContinuationPrepared", field: "expires_in", bound: "maximum", maximum: 120},
		{schema: "LoginStarted", field: "authorization_url", bound: "maxLength", maximum: 8192},
		{schema: "LoginCompleted", field: "return_path", bound: "maxLength", maximum: 256},
	} {
		field := profileMap(t, profileMap(t, profileMap(t, schemas, test.schema), "properties"), test.field)
		if field[test.bound] != test.maximum {
			t.Fatal("successful transport bound drifted", test.schema)
		}
	}
	paths := profileMap(t, document, "paths")
	landing := profileMap(t, paths, "/auth/v1/login/continue")
	headSuccess := profileMap(t, profileMap(t, profileMap(t, landing, "head"), "responses"), "200")
	if headSuccess["content"] != nil {
		t.Fatal("HEAD document manufactures a response body")
	}
	capture := profileMap(t, profileMap(t, profileMap(t, paths, "/auth/callback"), "get"), "responses")
	headers := profileMap(t, profileMap(t, capture, "303"), "headers")
	location := profileMap(t, profileMap(t, headers, "Location"), "schema")
	length := profileMap(t, profileMap(t, headers, "Content-Length"), "schema")
	if location["const"] != "/auth/v1/login/continue" || length["const"] != "0" {
		t.Fatal("capture document exposes callback custody or a response body")
	}
}

func TestLoginDocumentOwnsBytesAndPreservesManagement(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/auth/callback", "/auth/" + strings.Repeat("x", 250)} {
		body, err := openapi.LoginDocument(openapi.ManagementProfileConsoleCookiePrivateV1, path)
		if err != nil || !json.Valid(body) {
			t.Fatal("canonical callback document rejected", err)
		}
		again, err := openapi.LoginDocument(openapi.ManagementProfileConsoleCookiePrivateV1, path)
		if err != nil || !bytes.Equal(body, again) {
			t.Fatal("document rendering nondeterministic", err)
		}
		clear(body)
		third, err := openapi.LoginDocument(openapi.ManagementProfileConsoleCookiePrivateV1, path)
		if err != nil || !bytes.Equal(third, again) {
			t.Fatal("caller mutation escaped document ownership", err)
		}
	}
	// Existing exact resource-byte and profile-shape tests remain the stronger
	// baseline oracle; rendering login must not mutate either management asset.
	for _, profile := range []openapi.ManagementProfile{
		openapi.ManagementProfileBearerV1, openapi.ManagementProfileConsoleCookiePrivateV1,
	} {
		before, err := openapi.ManagementDocument(profile)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := openapi.LoginDocument(openapi.ManagementProfileConsoleCookiePrivateV1, "/auth/callback"); err != nil {
			t.Fatal(err)
		}
		after, err := openapi.ManagementDocument(profile)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("login rendering changed management contract", err)
		}
	}
}

func FuzzLoginDocumentSelection(f *testing.F) {
	f.Add("console-cookie-csrf-private-v1", "/auth/callback")
	f.Add("", "/auth/callback")
	f.Add("account-session-bearer-v1", "/auth/callback")
	f.Add("console-cookie-csrf-private-v1", "/auth/v1/login/start")
	f.Add("console-cookie-csrf-private-v1", "/auth/%63allback")
	f.Fuzz(func(t *testing.T, profile, path string) {
		body, err := openapi.LoginDocument(openapi.ManagementProfile(profile), path)
		if err != nil {
			if body != nil || !errors.Is(err, openapi.ErrInvalidLoginProfile) {
				t.Fatal("invalid selection released bytes or raw diagnostics")
			}
			return
		}
		if profile != "console-cookie-csrf-private-v1" || len(path) > 256 || !strings.HasPrefix(path, "/auth/") ||
			len(body) > 128<<10 || !json.Valid(body) {
			t.Fatal("arbitrary selection widened bounded private contract")
		}
		paths := profileMap(t, profileObject(t, body), "paths")
		if len(paths) != 5 || paths[path] == nil {
			t.Fatal("document callback diverged from selected path")
		}
	})
}

package openapi

import (
	_ "embed"
	"encoding/json"
	"errors"
	"path"
	"strings"
)

const loginCallbackTemplatePath = "/auth/v1/login/callback"

// ErrInvalidLoginProfile conceals unsupported selection, routing or compiled drift.
var ErrInvalidLoginProfile = errors.New("openapi: invalid login profile")

//go:embed login_console_private_v1.json
var loginConsolePrivateContract string

// LoginDocument renders only the private Console login source contract. The
// process supplies the SAME callback path selected by its validated dispatcher;
// never pass client input. Both management documents remain unchanged. Rendering
// enables no listener, documentation endpoint, auth profile or public SSO.
// Output is deterministic and independently owned; failure releases no bytes.
func LoginDocument(profile ManagementProfile, callbackPath string) ([]byte, error) {
	if profile != ManagementProfileConsoleCookiePrivateV1 {
		return nil, ErrInvalidLoginProfile
	}
	return composeLoginDocument(loginConsolePrivateContract, callbackPath)
}

func composeLoginDocument(asset, callbackPath string) ([]byte, error) {
	if len(asset) == 0 || len(asset) > maximumManagementDocumentBytes || !validLoginCallbackPath(callbackPath) {
		return nil, ErrInvalidLoginProfile
	}
	document, err := managementObject([]byte(asset))
	if err != nil {
		return nil, ErrInvalidLoginProfile
	}
	validVersion := string(document["openapi"]) == `"3.1.0"`
	validProfile := string(document["x-meshtransit-auth-profile"]) == `"console-cookie-csrf-private-v1"`
	privateStatus := string(document["x-meshtransit-runtime-status"]) == `"private-source-only"`
	if !validVersion || !validProfile || !privateStatus || document["security"] != nil {
		return nil, ErrInvalidLoginProfile
	}
	paths, err := managementObject(document["paths"])
	if err != nil || len(paths) != 5 {
		return nil, ErrInvalidLoginProfile
	}
	for route, operations := range map[string]map[string]string{
		"/auth/v1/login/prepare":          {"post": "prepareBrowserLogin"},
		"/auth/v1/login/start":            {"post": "startBrowserLogin"},
		loginCallbackTemplatePath:         {"get": "captureBrowserLoginCallback"},
		"/auth/v1/login/continue/prepare": {"post": "prepareBrowserLoginContinuation"},
		"/auth/v1/login/continue": {
			"get": "presentBrowserLoginContinuation", "head": "headBrowserLoginContinuation", "post": "completeBrowserLogin",
		},
	} {
		methods, err := managementObject(paths[route])
		if err != nil || len(methods) != len(operations) {
			return nil, ErrInvalidLoginProfile
		}
		for method, id := range operations {
			operation, err := managementObject(methods[method])
			var operationID string
			if err != nil || json.Unmarshal(operation["operationId"], &operationID) != nil || operationID != id {
				return nil, ErrInvalidLoginProfile
			}
			if !validLoginOperationSecurity(operation["security"], id) {
				return nil, ErrInvalidLoginProfile
			}
		}
	}
	callback := paths[loginCallbackTemplatePath]
	delete(paths, loginCallbackTemplatePath)
	if _, found := paths[callbackPath]; found {
		return nil, ErrInvalidLoginProfile
	}
	paths[callbackPath] = callback
	document["paths"], err = json.Marshal(paths)
	if err != nil {
		return nil, ErrInvalidLoginProfile
	}
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil || len(body) > maximumManagementDocumentBytes {
		return nil, ErrInvalidLoginProfile
	}
	return body, nil
}

func validLoginOperationSecurity(body json.RawMessage, operationID string) bool {
	expected := []string{}
	switch operationID {
	case "prepareBrowserLogin", "presentBrowserLoginContinuation", "headBrowserLoginContinuation":
	case "startBrowserLogin":
		expected = []string{"loginInitiationCookie", "loginIntentProof"}
	case "captureBrowserLoginCallback":
		expected = []string{"preAuthCookie"}
	case "prepareBrowserLoginContinuation":
		expected = []string{"preAuthCookie", "capturedCallbackCookie"}
	case "completeBrowserLogin":
		expected = []string{"preAuthCookie", "capturedCallbackCookie", "continuationIntentProof"}
	default:
		return false
	}
	var requirements []map[string][]string
	if json.Unmarshal(body, &requirements) != nil || requirements == nil {
		return false
	}
	if len(expected) == 0 {
		return len(requirements) == 0
	}
	if len(requirements) != 1 || len(requirements[0]) != len(expected) {
		return false
	}
	for _, name := range expected {
		scopes, found := requirements[0][name]
		if !found || scopes == nil || len(scopes) != 0 {
			return false
		}
	}
	return true
}

// This source-document profile deliberately mirrors the narrower dispatcher
// namespace/bounds, not general-purpose URL parsing or a provider trust rule.
func validLoginCallbackPath(value string) bool {
	if len(value) > 256 || !strings.HasPrefix(value, "/auth/") || path.Clean(value) != value {
		return false
	}
	for _, character := range value {
		letter := character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
		digit := character >= '0' && character <= '9'
		if !letter && !digit && !strings.ContainsRune("/-._~", character) {
			return false
		}
	}
	switch value {
	case "/auth/v1/login/prepare", "/auth/v1/login/start", "/auth/v1/login/continue",
		"/auth/v1/login/continue/prepare", consoleSessionPreparePath, consoleSessionLogoutPath,
		consoleSessionManagementScopesPath:
		return false
	default:
		return true
	}
}

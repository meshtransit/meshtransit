package openapi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestComposeConsoleManagementDocumentRejectsBaselineDrift(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		change func(map[string]json.RawMessage)
	}{
		{name: "wrong version", change: func(d map[string]json.RawMessage) { d["openapi"] = json.RawMessage(`"3.0.0"`) }},
		{name: "inherited security", change: func(d map[string]json.RawMessage) { d["security"] = json.RawMessage(`[]`) }},
		{name: "unknown resources", change: func(d map[string]json.RawMessage) { d["paths"] = json.RawMessage(`{}`) }},
		{name: "null paths", change: func(d map[string]json.RawMessage) { d["paths"] = json.RawMessage(`null`) }},
		{name: "null components", change: func(d map[string]json.RawMessage) { d["components"] = json.RawMessage(`null`) }},
		{name: "null info", change: func(d map[string]json.RawMessage) { d["info"] = json.RawMessage(`null`) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			document, err := managementObject([]byte(managementV1Contract))
			if err != nil {
				t.Fatal(err)
			}
			test.change(document)
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			body, err := composeConsoleManagementDocument(string(encoded), consolePrivateProfile)
			if body != nil || !errors.Is(err, ErrInvalidManagementProfile) {
				t.Fatal("unreviewed baseline released a partial document")
			}
		})
	}
	for _, test := range []struct{ name, base, fragment string }{
		{name: "empty base", fragment: consolePrivateProfile},
		{name: "invalid base", base: "{", fragment: consolePrivateProfile},
		{name: "large base", base: strings.Repeat(" ", maximumManagementDocumentBytes+1), fragment: consolePrivateProfile},
		{name: "empty fragment", base: managementV1Contract},
		{name: "invalid fragment", base: managementV1Contract, fragment: "{"},
		{name: "null fragment", base: managementV1Contract, fragment: "null"},
		{name: "wrong fragment identity", base: managementV1Contract, fragment: `{ "id": "other" }`},
		{name: "large fragment", base: managementV1Contract, fragment: strings.Repeat(" ", maximumManagementDocumentBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			body, err := composeConsoleManagementDocument(test.base, test.fragment)
			if body != nil || !errors.Is(err, ErrInvalidManagementProfile) {
				t.Fatal("incomplete/oversized compiled input released a document")
			}
		})
	}
}

func TestConsoleManagementOperationRejectsAuthenticationDrift(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, item string }{
		{name: "null operation", item: `null`},
		{name: "anonymous alternatives", item: `{"operationId":"revokeDevice","security":[{}]}`},
		{name: "cookie alternative", item: `{"operationId":"revokeDevice","security":[{"accountSessionCookie":[]}]}`},
		{name: "null scopes", item: `{"operationId":"revokeDevice","security":[{"accountSessionBearer":null}]}`},
		{name: "role scopes", item: `{"operationId":"revokeDevice","security":[{"accountSessionBearer":["admin"]}]}`},
		{name: "missing parameters", item: `{"operationId":"revokeDevice","security":[{"accountSessionBearer":[]}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			body, err := consoleManagementOperation(json.RawMessage(test.item), true)
			if body != nil || !errors.Is(err, ErrInvalidManagementProfile) {
				t.Fatal("unreviewed operation negotiated another transport")
			}
		})
	}
}

// profileWith returns the shipped profile after change.
func profileWith(t *testing.T, change func(map[string]any)) string {
	t.Helper()
	var profile map[string]any
	if err := json.Unmarshal([]byte(consolePrivateProfile), &profile); err != nil {
		t.Fatal(err)
	}
	change(profile)
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func profileOperation(profile map[string]any, path, method string) map[string]any {
	return profile["paths"].(map[string]any)[path].(map[string]any)[method].(map[string]any)
}

func TestComposeConsoleManagementDocumentRejectsProfileDrift(t *testing.T) {
	t.Parallel()
	const read = "/api/v1/workspaces/{workspace_id}/members"
	const change = "/api/v1/workspaces/{workspace_id}/role-assignments"
	cookie := []any{map[string]any{"accountSessionCookie": []any{}}}
	for _, test := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"older format", func(p map[string]any) { p["format"] = "meshtransit-management-auth-profile/v1" }},
		{"no paths", func(p map[string]any) { p["paths"] = map[string]any{} }},
		{"empty path item", func(p map[string]any) { p["paths"].(map[string]any)["/api/v1/empty"] = map[string]any{} }},
		{"unknown method", func(p map[string]any) {
			item := p["paths"].(map[string]any)[read].(map[string]any)
			item["trace"] = item["get"]
		}},
		{"read with a body", func(p map[string]any) { profileOperation(p, read, "get")["requestBody"] = map[string]any{} }},
		{"read with a proof", func(p map[string]any) {
			profileOperation(p, read, "get")["security"] = profileOperation(p, change, "post")["security"]
		}},
		{"change without a proof", func(p map[string]any) { profileOperation(p, change, "post")["security"] = cookie }},
		{"change without a body", func(p map[string]any) { delete(profileOperation(p, change, "post"), "requestBody") }},
		{"delete with a body", func(p map[string]any) {
			item := p["paths"].(map[string]any)[change].(map[string]any)
			item["delete"] = item["post"]
			delete(item, "post")
		}},
		{"change without the proof parameter", func(p map[string]any) {
			operation := profileOperation(p, change, "post")
			kept := []any{}
			for _, parameter := range operation["parameters"].([]any) {
				if parameter.(map[string]any)["$ref"] != "#/components/parameters/ConsoleSessionProof" {
					kept = append(kept, parameter)
				}
			}
			operation["parameters"] = kept
		}},
		{"read without the Origin parameter", func(p map[string]any) {
			operation := profileOperation(p, read, "get")
			kept := []any{}
			for _, parameter := range operation["parameters"].([]any) {
				if parameter.(map[string]any)["$ref"] != "#/components/parameters/ConsoleOrigin" {
					kept = append(kept, parameter)
				}
			}
			operation["parameters"] = kept
		}},
		{"repeated Origin parameter", func(p map[string]any) {
			operation := profileOperation(p, read, "get")
			operation["parameters"] = append(operation["parameters"].([]any),
				map[string]any{"$ref": "#/components/parameters/ConsoleOrigin"})
		}},
		{"duplicate operation ID", func(p map[string]any) {
			profileOperation(p, read, "get")["operationId"] = profileOperation(p, change, "post")["operationId"]
		}},
		{"operation ID of a bearer operation", func(p map[string]any) {
			profileOperation(p, read, "get")["operationId"] = "revokeDevice"
		}},
		{"unknown bearer operation", func(p map[string]any) {
			p["bearerOperations"] = append(p["bearerOperations"].([]any), "notAnOperation")
		}},
		{"repeated bearer operation", func(p map[string]any) {
			p["bearerOperations"] = append(p["bearerOperations"].([]any), "revokeDevice")
		}},
		{"no bearer operations", func(p map[string]any) { p["bearerOperations"] = []any{} }},
		{"profile replaces a bearer operation", func(p map[string]any) {
			path := "/api/v1/workspaces/{workspace_id}/networks/{network_id}/policy"
			p["paths"].(map[string]any)[path] = map[string]any{"get": profileOperation(p, read, "get")}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			body, err := composeConsoleManagementDocument(managementV1Contract, profileWith(t, test.change))
			if body != nil || !errors.Is(err, ErrInvalidManagementProfile) {
				t.Fatal("an unreviewed profile change released a document")
			}
		})
	}
}

func TestComposeConsoleManagementDocumentRejectsComponentCollision(t *testing.T) {
	t.Parallel()
	for _, section := range []string{"schemas", "parameters"} {
		t.Run(section, func(t *testing.T) {
			t.Parallel()
			document, err := managementObject([]byte(managementV1Contract))
			if err != nil {
				t.Fatal(err)
			}
			components, err := managementObject(document["components"])
			if err != nil {
				t.Fatal(err)
			}
			values, err := managementObject(components[section])
			if err != nil {
				t.Fatal(err)
			}
			values["ConsoleSessionProof"] = json.RawMessage(`{}`)
			components[section], err = json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			document["components"], err = json.Marshal(components)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			body, err := composeConsoleManagementDocument(string(encoded), consolePrivateProfile)
			if body != nil || !errors.Is(err, ErrInvalidManagementProfile) {
				t.Fatal("profile overwrote an existing resource component")
			}
		})
	}
}

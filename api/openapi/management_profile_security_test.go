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

func TestConsoleManagementOperationRejectsAuthenticationOrMethodDrift(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, item string }{
		{name: "null item", item: `null`},
		{name: "wrong method", item: `{"get":{}}`},
		{name: "extra method", item: `{"post":{},"get":{}}`},
		{name: "null operation", item: `{"post":null}`},
		{name: "operation identity", item: `{"post":{"operationId":"other"}}`},
		{name: "anonymous alternatives", item: `{"post":{"operationId":"revokeDevice","security":[{}]}}`},
		{name: "cookie alternative", item: `{"post":{
			"operationId":"revokeDevice","security":[{"accountSessionCookie":[]}]}}`},
		{name: "null scopes", item: `{"post":{"operationId":"revokeDevice","security":[{"accountSessionBearer":null}]}}`},
		{name: "role scopes", item: `{"post":{
			"operationId":"revokeDevice","security":[{"accountSessionBearer":["admin"]}]}}`},
		{name: "missing parameters", item: `{"post":{
			"operationId":"revokeDevice","security":[{"accountSessionBearer":[]}]}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			body, err := consoleManagementOperation(json.RawMessage(test.item), "revokeDevice")
			if body != nil || !errors.Is(err, ErrInvalidManagementProfile) {
				t.Fatal("unreviewed operation negotiated another transport or method")
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

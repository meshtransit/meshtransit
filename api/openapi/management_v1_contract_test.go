package openapi_test

import (
	"encoding/json"
	"os"
	"testing"
)

func TestManagementV1DeviceRevocationContract(t *testing.T) {
	t.Parallel()

	documentBytes, err := os.ReadFile("management_v1.json")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	var document struct {
		OpenAPI string `json:"openapi"`
		Paths   map[string]struct {
			Post struct {
				OperationID string                     `json:"operationId"`
				Security    []map[string][]string      `json:"security"`
				Responses   map[string]json.RawMessage `json:"responses"`
			} `json:"post"`
		} `json:"paths"`
		Components struct {
			SecuritySchemes map[string]struct {
				Type   string `json:"type"`
				Scheme string `json:"scheme"`
			} `json:"securitySchemes"`
		} `json:"components"`
	}
	if err := json.Unmarshal(documentBytes, &document); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	const path = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/devices/{device_id}/actions/revoke"
	operation, ok := document.Paths[path]
	if !ok || operation.Post.OperationID != "revokeDevice" {
		t.Fatalf("Device revoke operation = %+v, found=%t", operation.Post, ok)
	}
	if document.OpenAPI != "3.1.0" || len(operation.Post.Security) != 1 {
		t.Fatalf("OpenAPI/security contract = %q/%+v", document.OpenAPI, operation.Post.Security)
	}
	if _, ok := operation.Post.Security[0]["accountSessionBearer"]; !ok {
		t.Fatal("Device revoke operation does not require Account Session bearer authentication")
	}
	for _, status := range []string{"200", "400", "401", "403", "404", "405", "409", "412", "428", "503", "504"} {
		if _, ok := operation.Post.Responses[status]; !ok {
			t.Fatalf("Device revoke responses omit status %s", status)
		}
	}
	bearer, ok := document.Components.SecuritySchemes["accountSessionBearer"]
	if !ok || bearer.Type != "http" || bearer.Scheme != "bearer" {
		t.Fatalf("Account Session security scheme = %+v, found=%t", bearer, ok)
	}
}

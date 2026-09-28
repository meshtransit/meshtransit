package openapi_test

import (
	"encoding/json"
	"os"
	"testing"
)

func TestManagementV1MutationContracts(t *testing.T) {
	t.Parallel()

	documentBytes, err := os.ReadFile("management_v1.json")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	var document struct {
		OpenAPI string `json:"openapi"`
		Paths   map[string]struct {
			Get struct {
				OperationID string                     `json:"operationId"`
				Security    []map[string][]string      `json:"security"`
				Responses   map[string]json.RawMessage `json:"responses"`
			} `json:"get"`
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
	for _, status := range []string{"200", "400", "401", "403", "404", "405", "409", "412", "428", "429", "503", "504"} {
		if _, ok := operation.Post.Responses[status]; !ok {
			t.Fatalf("Device revoke responses omit status %s", status)
		}
	}
	const policyPath = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/policy/actions/publish"
	policyOperation, ok := document.Paths[policyPath]
	if !ok || policyOperation.Post.OperationID != "publishPolicy" {
		t.Fatalf("Policy publish operation = %+v, found=%t", policyOperation.Post, ok)
	}
	if len(policyOperation.Post.Security) != 1 {
		t.Fatalf("Policy publish security contract = %+v", policyOperation.Post.Security)
	}
	if _, ok := policyOperation.Post.Security[0]["accountSessionBearer"]; !ok {
		t.Fatal("Policy publish operation does not require Account Session bearer authentication")
	}
	for _, status := range []string{"200", "400", "401", "403", "405", "412", "428", "429", "503", "504"} {
		if _, ok := policyOperation.Post.Responses[status]; !ok {
			t.Fatalf("Policy publish responses omit status %s", status)
		}
	}
	for _, contract := range []struct {
		path, getOperation, postOperation string
	}{
		{
			path:         "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources",
			getOperation: "listResources", postOperation: "createResource",
		},
		{
			path:         "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resource-groups",
			getOperation: "listResourceGroups", postOperation: "createResourceGroup",
		},
	} {
		resourceOperation, found := document.Paths[contract.path]
		if !found || resourceOperation.Get.OperationID != contract.getOperation ||
			resourceOperation.Post.OperationID != contract.postOperation {
			t.Fatalf("Resource collection contract = %+v, found=%t", resourceOperation, found)
		}
		for _, security := range [][]map[string][]string{
			resourceOperation.Get.Security, resourceOperation.Post.Security,
		} {
			if len(security) != 1 || security[0]["accountSessionBearer"] == nil {
				t.Fatal("Resource collection operation does not require Account Session bearer authentication")
			}
		}
	}
	for _, contract := range []struct{ path, operation string }{
		{path: "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources/{resource_id}", operation: "getResource"},
		{path: "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resource-groups/{resource_group_id}", operation: "getResourceGroup"},
	} {
		resourceOperation, found := document.Paths[contract.path]
		if !found || resourceOperation.Get.OperationID != contract.operation ||
			len(resourceOperation.Get.Security) != 1 ||
			resourceOperation.Get.Security[0]["accountSessionBearer"] == nil {
			t.Fatalf("Resource detail contract = %+v, found=%t", resourceOperation.Get, found)
		}
	}
	for _, contract := range []struct{ path, operation string }{
		{
			path:      "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources/{resource_id}/actions/{lifecycle_action}",
			operation: "transitionResourceLifecycle",
		},
		{
			path:      "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resource-groups/{resource_group_id}/actions/{lifecycle_action}",
			operation: "transitionResourceGroupLifecycle",
		},
	} {
		lifecycleOperation, found := document.Paths[contract.path]
		if !found || lifecycleOperation.Post.OperationID != contract.operation ||
			len(lifecycleOperation.Post.Security) != 1 ||
			lifecycleOperation.Post.Security[0]["accountSessionBearer"] == nil {
			t.Fatalf("Resource lifecycle contract = %+v, found=%t", lifecycleOperation.Post, found)
		}
		for _, status := range []string{
			"200", "400", "401", "403", "404", "405", "409", "412", "428", "429", "503", "504",
		} {
			if _, ok := lifecycleOperation.Post.Responses[status]; !ok {
				t.Fatalf("Resource lifecycle responses omit status %s", status)
			}
		}
	}
	bearer, ok := document.Components.SecuritySchemes["accountSessionBearer"]
	if !ok || bearer.Type != "http" || bearer.Scheme != "bearer" {
		t.Fatalf("Account Session security scheme = %+v, found=%t", bearer, ok)
	}
}

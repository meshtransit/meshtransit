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
				OperationID string                `json:"operationId"`
				Security    []map[string][]string `json:"security"`
				Parameters  []struct {
					Ref string `json:"$ref"`
				} `json:"parameters"`
				Responses map[string]json.RawMessage `json:"responses"`
			} `json:"post"`
		} `json:"paths"`
		Components struct {
			SecuritySchemes map[string]struct {
				Type   string `json:"type"`
				Scheme string `json:"scheme"`
			} `json:"securitySchemes"`
			Schemas map[string]json.RawMessage `json:"schemas"`
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
	for _, status := range []string{"200", "400", "401", "403", "405", "409", "412", "428", "429", "503", "504"} {
		if _, ok := policyOperation.Post.Responses[status]; !ok {
			t.Fatalf("Policy publish responses omit status %s", status)
		}
	}
	const explainPath = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/access-graph/actions/explain"
	explainOperation, ok := document.Paths[explainPath]
	if !ok || explainOperation.Post.OperationID != "explainActivePolicy" {
		t.Fatalf("Policy explanation operation = %+v, found=%t", explainOperation.Post, ok)
	}
	if len(explainOperation.Post.Security) != 1 ||
		explainOperation.Post.Security[0]["accountSessionBearer"] == nil {
		t.Fatal("Policy explanation does not require Account Session bearer authentication")
	}
	for _, status := range []string{"200", "400", "401", "403", "405", "429", "500", "503", "504"} {
		if _, ok := explainOperation.Post.Responses[status]; !ok {
			t.Fatalf("Policy explanation responses omit status %s", status)
		}
	}
	for _, schema := range []string{
		"ExplainPolicyRequest", "ExplainPolicyResponse", "ExplainedPolicy",
		"ExplainedPolicyEvidence", "ExplainedPolicyPath",
	} {
		if document.Components.Schemas[schema] == nil {
			t.Fatalf("Policy explanation schema %s is absent", schema)
		}
	}
	var policyRule struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
		OneOf      []struct {
			Required []string `json:"required"`
			Not      struct {
				AnyOf []struct {
					Required []string `json:"required"`
				} `json:"anyOf"`
			} `json:"not"`
		} `json:"oneOf"`
	}
	if err := json.Unmarshal(document.Components.Schemas["CompiledPolicyRule"], &policyRule); err != nil {
		t.Fatalf("decode CompiledPolicyRule: %v", err)
	}
	if len(policyRule.OneOf) != 3 || policyRule.Properties["destination_device_id"] == nil ||
		policyRule.Properties["destination_resource_id"] == nil ||
		policyRule.Properties["destination_resource_group_id"] == nil ||
		len(policyRule.OneOf[0].Required) != 1 ||
		policyRule.OneOf[0].Required[0] != "destination_device_id" ||
		len(policyRule.OneOf[0].Not.AnyOf) != 2 ||
		policyRule.OneOf[0].Not.AnyOf[0].Required[0] != "destination_resource_id" ||
		policyRule.OneOf[0].Not.AnyOf[1].Required[0] != "destination_resource_group_id" ||
		len(policyRule.OneOf[1].Required) != 1 ||
		policyRule.OneOf[1].Required[0] != "destination_resource_id" ||
		len(policyRule.OneOf[1].Not.AnyOf) != 2 ||
		policyRule.OneOf[1].Not.AnyOf[0].Required[0] != "destination_device_id" ||
		policyRule.OneOf[1].Not.AnyOf[1].Required[0] != "destination_resource_group_id" ||
		len(policyRule.OneOf[2].Required) != 1 ||
		policyRule.OneOf[2].Required[0] != "destination_resource_group_id" ||
		len(policyRule.OneOf[2].Not.AnyOf) != 2 ||
		policyRule.OneOf[2].Not.AnyOf[0].Required[0] != "destination_device_id" ||
		policyRule.OneOf[2].Not.AnyOf[1].Required[0] != "destination_resource_id" {
		t.Fatalf("CompiledPolicyRule typed destination contract = %+v", policyRule)
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
	for _, contract := range []struct {
		path, operation string
		statuses        []string
	}{
		{
			path:      "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources/{resource_id}/actions/preview-rebind",
			operation: "previewResourceRebind",
			statuses:  []string{"200", "400", "401", "403", "404", "405", "409", "412", "422", "428", "429", "503", "504"},
		},
		{
			path:      "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources/{resource_id}/actions/rebind",
			operation: "rebindResource",
			statuses:  []string{"200", "400", "401", "403", "404", "405", "409", "412", "422", "428", "429", "503", "504"},
		},
		{
			path:      "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resource-groups/{resource_group_id}/actions/preview-replace",
			operation: "previewResourceGroupReplacement",
			statuses:  []string{"200", "400", "401", "403", "404", "405", "409", "412", "428", "429", "503", "504"},
		},
		{
			path:      "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resource-groups/{resource_group_id}/actions/replace",
			operation: "replaceResourceGroupDefinition",
			statuses:  []string{"200", "400", "401", "403", "404", "405", "409", "412", "428", "429", "503", "504"},
		},
	} {
		rebindOperation, found := document.Paths[contract.path]
		if !found || rebindOperation.Post.OperationID != contract.operation ||
			len(rebindOperation.Post.Security) != 1 ||
			rebindOperation.Post.Security[0]["accountSessionBearer"] == nil {
			t.Fatalf("Resource rebind contract = %+v, found=%t", rebindOperation.Post, found)
		}
		for _, status := range contract.statuses {
			if _, ok := rebindOperation.Post.Responses[status]; !ok {
				t.Fatalf("Resource rebind responses omit status %s", status)
			}
		}
	}
	for _, contract := range []struct {
		path, operation, success string
		confirmation             bool
	}{
		{
			path:      "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources/{resource_id}/actions/preview-authority-change",
			operation: "previewResourceAuthorityChange", success: "200",
		},
		{
			path:      "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources/{resource_id}/actions/request-authority-change",
			operation: "requestResourceAuthorityChange", success: "202",
		},
		{
			path:      "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resources/{resource_id}/actions/confirm-authority-change",
			operation: "confirmResourceAuthorityChange", success: "200", confirmation: true,
		},
		{
			path:      "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resource-groups/{resource_group_id}/actions/preview-authority-change",
			operation: "previewResourceGroupAuthorityChange", success: "200",
		},
		{
			path:      "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resource-groups/{resource_group_id}/actions/request-authority-change",
			operation: "requestResourceGroupAuthorityChange", success: "202",
		},
		{
			path:      "/api/v1/workspaces/{workspace_id}/networks/{network_id}/resource-groups/{resource_group_id}/actions/confirm-authority-change",
			operation: "confirmResourceGroupAuthorityChange", success: "200", confirmation: true,
		},
	} {
		operation, found := document.Paths[contract.path]
		if !found || operation.Post.OperationID != contract.operation ||
			len(operation.Post.Security) != 1 ||
			operation.Post.Security[0]["accountSessionBearer"] == nil {
			t.Fatalf("authority-change contract = %+v, found=%t", operation.Post, found)
		}
		statuses := []string{
			contract.success, "400", "401", "403", "404", "405", "409", "412",
			"428", "429", "503", "504",
		}
		if contract.confirmation {
			statuses = append(statuses, "410")
		}
		for _, status := range statuses {
			if _, ok := operation.Post.Responses[status]; !ok {
				t.Fatalf("authority-change responses omit status %s for %s", status, contract.operation)
			}
		}
		parameters := make(map[string]bool, len(operation.Post.Parameters))
		for _, parameter := range operation.Post.Parameters {
			parameters[parameter.Ref] = true
		}
		ifMatch := "#/components/parameters/AggregateIfMatch"
		if contract.confirmation {
			ifMatch = "#/components/parameters/AuthorityChangeRequestIfMatch"
		}
		if !parameters[ifMatch] {
			t.Fatalf("authority-change operation %s omits %s", contract.operation, ifMatch)
		}
		hasIdempotencyKey := parameters["#/components/parameters/IdempotencyKey"]
		mutation := contract.success == "202" || contract.confirmation
		if hasIdempotencyKey != mutation {
			t.Fatalf("authority-change operation %s idempotency parameter = %t, want %t",
				contract.operation, hasIdempotencyKey, mutation)
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

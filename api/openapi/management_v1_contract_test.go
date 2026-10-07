package openapi_test

import (
	"encoding/json"
	"os"
	"slices"
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
				OperationID string                `json:"operationId"`
				Security    []map[string][]string `json:"security"`
				Parameters  []struct {
					Ref string `json:"$ref"`
				} `json:"parameters"`
				Responses map[string]json.RawMessage `json:"responses"`
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
	var publishRequest struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(document.Components.Schemas["PublishPolicyRequest"], &publishRequest); err != nil {
		t.Fatalf("decode PublishPolicyRequest: %v", err)
	}
	if publishRequest.Properties["approval_evidence_id"] == nil ||
		slices.Contains(publishRequest.Required, "approval_evidence_id") {
		t.Fatal("Policy publication must permit direct authorized publication and retain optional immutable approval evidence")
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
		"ExplainedPolicyTarget", "ExplainedPolicyEvidence", "ExplainedPolicyPath",
	} {
		if document.Components.Schemas[schema] == nil {
			t.Fatalf("Policy explanation schema %s is absent", schema)
		}
	}
	type typedSelectorBranch struct {
		Required []string `json:"required"`
		Not      struct {
			AnyOf []struct {
				Required []string `json:"required"`
			} `json:"anyOf"`
		} `json:"not"`
	}
	var explainRequest struct {
		Properties map[string]json.RawMessage `json:"properties"`
		AllOf      []struct {
			OneOf []typedSelectorBranch `json:"oneOf"`
		} `json:"allOf"`
	}
	if err := json.Unmarshal(document.Components.Schemas["ExplainPolicyRequest"], &explainRequest); err != nil {
		t.Fatalf("decode ExplainPolicyRequest: %v", err)
	}
	if len(explainRequest.AllOf) < 1 || len(explainRequest.AllOf[0].OneOf) != 3 ||
		explainRequest.Properties["destination_device_id"] == nil ||
		explainRequest.Properties["destination_resource_id"] == nil ||
		explainRequest.Properties["destination_imported_resource_id"] == nil ||
		len(explainRequest.AllOf[0].OneOf[2].Required) != 1 ||
		explainRequest.AllOf[0].OneOf[2].Required[0] != "destination_imported_resource_id" ||
		len(explainRequest.AllOf[0].OneOf[2].Not.AnyOf) != 2 {
		t.Fatalf("ExplainPolicyRequest typed destination contract = %+v", explainRequest)
	}
	var explainTarget struct {
		Properties map[string]json.RawMessage `json:"properties"`
		OneOf      []typedSelectorBranch      `json:"oneOf"`
	}
	if err := json.Unmarshal(document.Components.Schemas["ExplainedPolicyTarget"], &explainTarget); err != nil {
		t.Fatalf("decode ExplainedPolicyTarget: %v", err)
	}
	if len(explainTarget.OneOf) != 3 || explainTarget.Properties["device_id"] == nil ||
		explainTarget.Properties["resource_id"] == nil ||
		explainTarget.Properties["imported_resource_id"] == nil ||
		len(explainTarget.OneOf[2].Required) != 1 ||
		explainTarget.OneOf[2].Required[0] != "imported_resource_id" ||
		len(explainTarget.OneOf[2].Not.AnyOf) != 2 {
		t.Fatalf("ExplainedPolicyTarget typed destination contract = %+v", explainTarget)
	}
	var policyRule struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
		AllOf      []struct {
			OneOf []exclusiveAlternative `json:"oneOf"`
		} `json:"allOf"`
		OneOf []exclusiveAlternative `json:"oneOf"`
	}
	if err := json.Unmarshal(document.Components.Schemas["CompiledPolicyRule"], &policyRule); err != nil {
		t.Fatalf("decode CompiledPolicyRule: %v", err)
	}
	// Each destination alternative requires its own key and excludes every other one.
	destinations := []string{
		"destination_device_id", "destination_device_group_id", "destination_device_tag_id",
		"destination_resource_id", "destination_resource_group_id", "destination_imported_resource_id",
	}
	sources := []string{
		"source_device_id", "source_device_group_id", "source_identity_group_id", "source_device_tag_id",
	}
	if len(policyRule.OneOf) != len(destinations) || len(policyRule.AllOf) != 1 ||
		len(policyRule.AllOf[0].OneOf) != len(sources) {
		t.Fatalf("CompiledPolicyRule typed selector contract = %+v", policyRule)
	}
	for index, alternative := range policyRule.AllOf[0].OneOf {
		if len(alternative.Required) != 1 || alternative.Required[0] != sources[index] ||
			policyRule.Properties[sources[index]] == nil || len(alternative.Not.AnyOf) != len(sources)-1 {
			t.Fatalf("CompiledPolicyRule typed source contract = %+v", alternative)
		}
	}
	seen := map[string]bool{}
	for _, alternative := range policyRule.OneOf {
		if len(alternative.Required) != 1 || policyRule.Properties[alternative.Required[0]] == nil ||
			len(alternative.Not.AnyOf) != len(destinations)-1 {
			t.Fatalf("CompiledPolicyRule typed destination contract = %+v", policyRule)
		}
		seen[alternative.Required[0]] = true
		for _, excluded := range alternative.Not.AnyOf {
			if len(excluded.Required) != 1 || excluded.Required[0] == alternative.Required[0] {
				t.Fatalf("CompiledPolicyRule destination %s exclusions = %+v", alternative.Required[0], alternative.Not.AnyOf)
			}
		}
	}
	for _, destination := range destinations {
		if !seen[destination] {
			t.Fatalf("CompiledPolicyRule lacks destination %s", destination)
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
	const shareCollectionPath = "/api/v1/workspaces/{workspace_id}/networks/{network_id}/share-offers"
	shareCollection, found := document.Paths[shareCollectionPath]
	if !found || shareCollection.Get.OperationID != "listShareOffers" ||
		shareCollection.Post.OperationID != "createShareOffer" {
		t.Fatalf("Share Offer collection contract = %+v, found=%t", shareCollection, found)
	}
	for _, security := range [][]map[string][]string{
		shareCollection.Get.Security, shareCollection.Post.Security,
	} {
		if len(security) != 1 || security[0]["accountSessionBearer"] == nil {
			t.Fatal("Share Offer collection does not require Account Session bearer authentication")
		}
	}
	for _, status := range []string{"201", "400", "401", "403", "405", "409", "429", "503", "504"} {
		if shareCollection.Post.Responses[status] == nil {
			t.Fatalf("Share Offer creation responses omit status %s", status)
		}
	}
	for _, contract := range []struct {
		path, operation string
		read            bool
	}{
		{path: shareCollectionPath + "/{share_offer_id}", operation: "getShareOffer", read: true},
		{path: shareCollectionPath + "/{share_offer_id}/actions/{share_offer_action}", operation: "decideShareOffer"},
		{path: "/api/v1/workspaces/{workspace_id}/networks/{network_id}/trust-contracts/{trust_contract_id}/actions/revoke", operation: "revokeTrustContract"},
	} {
		operation, ok := document.Paths[contract.path]
		if !ok {
			t.Fatalf("sharing path %s is absent", contract.path)
		}
		if contract.read {
			if operation.Get.OperationID != contract.operation || len(operation.Get.Security) != 1 ||
				operation.Get.Security[0]["accountSessionBearer"] == nil {
				t.Fatalf("sharing read contract = %+v", operation.Get)
			}
			continue
		}
		if operation.Post.OperationID != contract.operation || len(operation.Post.Security) != 1 ||
			operation.Post.Security[0]["accountSessionBearer"] == nil {
			t.Fatalf("sharing mutation contract = %+v", operation.Post)
		}
		for _, status := range []string{
			"200", "400", "401", "403", "404", "405", "409", "412", "428", "429", "503", "504",
		} {
			if operation.Post.Responses[status] == nil {
				t.Fatalf("sharing mutation %s omits status %s", contract.operation, status)
			}
		}
	}
	for _, schema := range []string{
		"CreateShareOfferRequest", "DecideShareOfferRequest", "RevokeTrustContractRequest",
		"ShareOffer", "ShareOfferResponse", "ShareOfferListResponse",
		"TrustContract", "TrustContractResponse",
	} {
		if document.Components.Schemas[schema] == nil {
			t.Fatalf("Resource Sharing schema %s is absent", schema)
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

// exclusiveAlternative is a oneOf branch that requires one key and excludes
// the others.
type exclusiveAlternative struct {
	Required []string `json:"required"`
	Not      struct {
		AnyOf []struct {
			Required []string `json:"required"`
		} `json:"anyOf"`
	} `json:"not"`
}

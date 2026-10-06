package openapi

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// TestManagementV1ExplainContextContract pins the Policy Explain denial and
// shared-destination contract: closed deny reasons, a context that names only
// the caller's participants, and shared paths without a destination Device.
func TestManagementV1ExplainContextContract(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("management_v1.json")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	var document struct {
		Components struct {
			Schemas map[string]json.RawMessage `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	type schema struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
		Enum       []string                   `json:"enum"`
	}
	decode := func(name string) schema {
		t.Helper()
		var value schema
		body := document.Components.Schemas[name]
		if body == nil {
			t.Fatalf("schema %s is absent", name)
		}
		if err := json.Unmarshal(body, &value); err != nil {
			t.Fatalf("schema %s: %v", name, err)
		}
		return value
	}
	property := func(owner schema, name string) schema {
		t.Helper()
		var value schema
		if err := json.Unmarshal(owner.Properties[name], &value); err != nil || owner.Properties[name] == nil {
			t.Fatalf("property %s is absent or invalid: %v", name, err)
		}
		return value
	}

	explained := decode("ExplainedPolicy")
	wantDenyReasons := []string{
		"no_active_release", "source_inactive", "target_inactive", "share_activating",
		"share_ended", "share_expired", "no_matching_active_rule",
	}
	if denyReason := property(explained, "deny_reason"); !slices.Equal(denyReason.Enum, wantDenyReasons) ||
		slices.Contains(explained.Required, "deny_reason") || !slices.Contains(explained.Required, "context") {
		t.Fatalf("deny_reason = %v, required = %v", denyReason.Enum, explained.Required)
	}
	context := decode("ExplainedPolicyContext")
	if !slices.Equal(context.Required, []string{"source", "target", "share"}) {
		t.Fatalf("context required = %v", context.Required)
	}
	if state := decode("ExplainedPolicyParticipantState"); !slices.Equal(state.Enum, []string{"active", "inactive", "missing"}) {
		t.Fatalf("participant states = %v", state.Enum)
	}
	share := decode("ExplainedPolicyShare")
	for _, field := range []string{"trust_contract_id", "state", "expires_at", "provider_workspace_code",
		"provider_network_code", "access_name"} {
		if !slices.Contains(share.Required, field) {
			t.Fatalf("share omits required %s", field)
		}
	}
	for _, leaked := range []string{"provider_device_id", "provider_resource_id", "address", "endpoint"} {
		if share.Properties[leaked] != nil {
			t.Fatalf("share exposes provider topology field %s", leaked)
		}
	}
	path := decode("ExplainedPolicyPath")
	if slices.Contains(path.Required, "destination_device_id") ||
		!slices.Contains(property(path, "selector_kind").Enum, "imported_resource") ||
		path.Properties["destination_imported_resource_id"] == nil || path.Properties["trust_contract_id"] == nil {
		t.Fatalf("ExplainedPolicyPath = %+v", path)
	}
}

// TestManagementV1AccessGraphListingContract pins the graph listing: bounded
// pages, nodes that name only the caller's participants, and a nullable
// continuation token.
func TestManagementV1AccessGraphListingContract(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("management_v1.json")
	if err != nil {
		t.Fatalf("os.ReadFile() error = %v", err)
	}
	var document struct {
		Paths      map[string]map[string]json.RawMessage `json:"paths"`
		Components struct {
			Schemas map[string]struct {
				Required   []string                   `json:"required"`
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	item := document.Paths["/api/v1/workspaces/{workspace_id}/networks/{network_id}/access-graph"]
	if item["get"] == nil || len(item) != 1 {
		t.Fatalf("access graph path item = %v", item)
	}
	listing := document.Components.Schemas["AccessGraphListing"]
	for _, field := range []string{"evidence", "nodes", "paths", "matching_paths", "next_page_token"} {
		if !slices.Contains(listing.Required, field) {
			t.Fatalf("listing omits required %s", field)
		}
	}
	graphNode := document.Components.Schemas["AccessGraphNode"]
	if len(graphNode.Properties) != 5 || graphNode.Properties["address"] != nil ||
		graphNode.Properties["provider_device_id"] != nil {
		t.Fatalf("graph node exposes %v", graphNode.Properties)
	}
	var nodes struct {
		MaxItems int `json:"maxItems"`
	}
	if err := json.Unmarshal(listing.Properties["nodes"], &nodes); err != nil || nodes.MaxItems != 1000 {
		t.Fatalf("nodes bound = %d, %v", nodes.MaxItems, err)
	}
}

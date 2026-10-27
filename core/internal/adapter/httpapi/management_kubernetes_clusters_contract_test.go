package httpapi

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	"meshtransit.net/api/openapi"
	"meshtransit.net/core/internal/domain/kubecluster"
)

// jsonFields lists the JSON names of a body type's fields, sorted.
func jsonFields(value any) []string {
	kind := reflect.TypeOf(value)
	fields := make([]string, 0, kind.NumField())
	for index := range kind.NumField() {
		name, _, _ := strings.Cut(kind.Field(index).Tag.Get("json"), ",")
		fields = append(fields, name)
	}
	slices.Sort(fields)
	return fields
}

type openAPISchema struct {
	Required   []string                 `json:"required"`
	Properties map[string]openAPISchema `json:"properties"`
	Items      *openAPISchema           `json:"items"`
	Enum       []string                 `json:"enum"`
}

func (schema openAPISchema) names() []string {
	names := make([]string, 0, len(schema.Properties))
	for name := range schema.Properties {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// The cluster's read, key warnings included, says exactly what the
// published management contract says (schema 229).
func TestKubernetesClusterReadMatchesTheContract(t *testing.T) {
	t.Parallel()
	document, err := openapi.ManagementDocument(openapi.ManagementProfileBearerV1)
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Content map[string]struct {
					Schema openAPISchema `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(document, &contract); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/workspaces/{workspace_id}/networks/{network_id}/kubernetes-clusters/{cluster_id}"
	data := contract.Paths[path]["get"].Responses["200"].Content["application/json"].Schema.Properties["data"]
	if got, want := data.names(), jsonFields(kubernetesClusterDetailBody{}); !slices.Equal(got, want) {
		t.Fatalf("contract fields %v, body fields %v", got, want)
	}
	required := slices.Clone(data.Required)
	slices.Sort(required)
	if !slices.Equal(required, jsonFields(kubernetesClusterDetailBody{})) {
		t.Fatalf("contract requires %v", required)
	}
	warnings := data.Properties["key_warnings"]
	if got, want := warnings.names(), jsonFields(kubernetesKeyWarningsBody{}); !slices.Equal(got, want) {
		t.Fatalf("key_warnings fields %v, body %v", got, want)
	}
	device := warnings.Properties["devices"].Items
	if device == nil {
		t.Fatal("key_warnings.devices has no items")
	}
	if got, want := device.names(), jsonFields(kubernetesKeyWarningBody{}); !slices.Equal(got, want) {
		t.Fatalf("key warning fields %v, body %v", got, want)
	}
	for _, reason := range device.Properties["last_reason"].Enum {
		if !kubecluster.KeyEventReason(reason).IsKnown() {
			t.Errorf("the contract names reason %q", reason)
		}
	}
	for _, state := range device.Properties["key_state"].Enum {
		if !kubecluster.ReportedKeyState(state).IsKnown() {
			t.Errorf("the contract names key state %q", state)
		}
	}
	if len(device.Properties["last_reason"].Enum) != 4 || len(device.Properties["key_state"].Enum) != 5 {
		t.Fatalf("contract enums %v %v", device.Properties["last_reason"].Enum, device.Properties["key_state"].Enum)
	}
}

// The signing read says exactly what the published contract says (K1.1).
func TestKubernetesClusterSigningMatchesTheContract(t *testing.T) {
	t.Parallel()
	document, err := openapi.ManagementDocument(openapi.ManagementProfileBearerV1)
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Content map[string]struct {
					Schema openAPISchema `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(document, &contract); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/workspaces/{workspace_id}/networks/{network_id}/kubernetes-clusters/{cluster_id}/signing"
	data := contract.Paths[path]["get"].Responses["200"].Content["application/json"].Schema.Properties["data"]
	required := slices.Clone(data.Required)
	slices.Sort(required)
	if got, want := data.names(), jsonFields(kubernetesSigningBody{}); !slices.Equal(got, want) ||
		!slices.Equal(required, want) {
		t.Fatalf("contract fields %v, required %v, body fields %v", got, required, want)
	}
	for name, body := range map[string]any{"trust": kubernetesSigningTrustBody{},
		"token_warnings": kubernetesKeyWarningsBody{}} {
		if got, want := data.Properties[name].names(), jsonFields(body); !slices.Equal(got, want) {
			t.Errorf("%s fields %v, body %v", name, got, want)
		}
	}
	for name, body := range map[string]any{"replicas": kubernetesSigningReplica{},
		"replica_requests": kubernetesSigningRequest{}} {
		items := data.Properties[name].Items
		if items == nil {
			t.Fatalf("%s has no items", name)
		}
		if got, want := items.names(), jsonFields(body); !slices.Equal(got, want) {
			t.Errorf("%s fields %v, body %v", name, got, want)
		}
	}
	states := data.Properties["replica_requests"].Items.Properties["trust_state"].Enum
	for _, state := range []kubecluster.RequestTrustState{kubecluster.RequestSetsTrust, kubecluster.RequestMatchesTrust,
		kubecluster.RequestDiffersFromTrust, kubecluster.RequestMustJoinAgain, kubecluster.RequestPodHeld} {
		if !slices.Contains(states, string(state)) {
			t.Errorf("the contract lacks trust state %q", state)
		}
	}
	device := data.Properties["token_warnings"].Properties["devices"].Items
	if device == nil || len(device.Properties["last_reason"].Enum) != 9 {
		t.Fatalf("token warning reasons %+v", device)
	}
	for _, reason := range device.Properties["last_reason"].Enum {
		if !kubecluster.KeyEventReason(reason).TokenRefused() {
			t.Errorf("the contract names reason %q", reason)
		}
	}
}

// The trust's own read and its keys say what the contract says (K1.1b).
func TestKubernetesSigningTrustMatchesTheContract(t *testing.T) {
	t.Parallel()
	document, err := openapi.ManagementDocument(openapi.ManagementProfileBearerV1)
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Paths map[string]map[string]struct {
			Responses map[string]struct {
				Content map[string]struct {
					Schema openAPISchema `json:"schema"`
				} `json:"content"`
			} `json:"responses"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(document, &contract); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/workspaces/{workspace_id}/networks/{network_id}/kubernetes-clusters/{cluster_id}/signing-trust"
	data := contract.Paths[path]["get"].Responses["200"].Content["application/json"].Schema.Properties["data"]
	if got, want := data.names(), jsonFields(kubernetesSigningTrustRead{}); !slices.Equal(got, want) {
		t.Fatalf("GET fields %v, body %v", got, want)
	}
	trust := data.Properties["trust"]
	if got, want := trust.names(), jsonFields(kubernetesSigningTrustBody{}); !slices.Equal(got, want) {
		t.Fatalf("trust fields %v, body %v", got, want)
	}
	keys := trust.Properties["keys"].Items
	if keys == nil {
		t.Fatal("trust.keys has no items")
	}
	if got, want := keys.names(), jsonFields(kubernetesTrustKeyBody{}); !slices.Equal(got, want) {
		t.Fatalf("key fields %v, body %v", got, want)
	}
	put := contract.Paths[path]["put"].Responses["200"].Content["application/json"].Schema.Properties["data"]
	if got := put.names(); !slices.Equal(got, []string{"changed", "trust"}) {
		t.Fatalf("PUT fields %v", got)
	}
}

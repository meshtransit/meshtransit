package httpapi

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/policy/compilation"
	policypublication "meshtransit.net/core/internal/domain/policy/publication"
)

const (
	accessPolicyPath = "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/networks/" +
		"01890f00-0000-7000-8000-000000000201/policy/actions/publish"
	// consoleClusterRule is a rule to a cluster exactly as the Console of
	// K1a3 to K2e sends it again: its groups, no access (K2 §24.1 H1).
	consoleClusterRule = `{"id":"01890f00-0000-7000-8000-000000000801",` +
		`"source_device_group_id":"01890f00-0000-7000-8000-000000000a01",` +
		`"destination_kubernetes_cluster_id":"01890f00-0000-7000-8000-000000000f01",` +
		`"kubernetes_groups":["edit","view"],"protocol":"tcp",` +
		`"destination_port_ranges":[{"first":443,"last":443}]}`
)

func decodeAccessPublication(t *testing.T, body string) (decodedPolicyPublication, *managementError) {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, accessPolicyPath, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", `"4"`)
	path, ok := parsePolicyPublishPath(request)
	if !ok {
		t.Fatal("path")
	}
	return decodePolicyPublicationRequest(httptest.NewRecorder(), request, path)
}

func withAccess(access string) string {
	return strings.Replace(consoleClusterRule, `"protocol"`, `"kubernetes_access":`+access+`,"protocol"`, 1)
}

// The current Console's payload keeps both the profile set and each rule's
// access; a body may name the profiles and how each rule applies one.
func TestPolicyPublicationDecodesKubernetesAccess(t *testing.T) {
	t.Parallel()
	decoded, failure := decodeAccessPublication(t, `{"reason":"keep","rules":[`+consoleClusterRule+`]}`)
	if failure != nil || decoded.request.KubernetesProfiles() != nil ||
		decoded.request.Rules()[0].KubernetesAccess() != nil {
		t.Fatalf("console payload = %+v, %v", decoded.request, failure)
	}
	profile := `{"id":"01890f00-0000-7000-8000-000000000c01","name":"developer","description":"team pods",` +
		`"namespaced":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list"]}]}`
	decoded, failure = decodeAccessPublication(t, `{"reason":"profile","kubernetes_profiles":[`+profile+`],"rules":[`+
		withAccess(`{"profile_id":"01890f00-0000-7000-8000-000000000c01","namespaces":["team-a"],`+
			`"mode":"report","report_until":"2026-11-02T00:00:00.123Z"}`)+`]}`)
	if failure != nil {
		t.Fatal(failure)
	}
	access := decoded.request.Rules()[0].KubernetesAccess()
	if profiles := decoded.request.KubernetesProfiles(); len(profiles) != 1 || profiles[0].Name() != "developer" ||
		access == nil || !access.Report || access.ReportUntil.UnixMilli() != 1_793_577_600_123 ||
		access.ProfileID != profiles[0].ID() {
		t.Fatalf("profile payload = %+v", access)
	}
	if decoded, failure = decodeAccessPublication(t, `{"reason":"none","kubernetes_profiles":[],"rules":[]}`); failure != nil ||
		decoded.request.KubernetesProfiles() == nil {
		t.Fatalf("an empty set keeps nothing: %v", failure)
	}
	if decoded, failure = decodeAccessPublication(t, `{"reason":"full","rules":[`+withAccess(`{"full":true}`)+`]}`); failure != nil ||
		!decoded.request.Rules()[0].KubernetesAccess().Full {
		t.Fatalf("full = %v", failure)
	}
	for name, body := range map[string]string{
		"empty access":        withAccess(`{}`),
		"full false":          withAccess(`{"full":false}`),
		"full with profile":   withAccess(`{"full":true,"profile_id":"01890f00-0000-7000-8000-000000000c01"}`),
		"no namespaces":       withAccess(`{"profile_id":"01890f00-0000-7000-8000-000000000c01"}`),
		"unknown mode":        withAccess(`{"profile_id":"01890f00-0000-7000-8000-000000000c01","namespaces":["a"],"mode":"audit"}`),
		"report, no deadline": withAccess(`{"profile_id":"01890f00-0000-7000-8000-000000000c01","namespaces":["a"],"mode":"report"}`),
		"deadline, enforcing": withAccess(`{"profile_id":"01890f00-0000-7000-8000-000000000c01","namespaces":["a"],"report_until":"2026-11-02T00:00:00Z"}`),
		"bad deadline":        withAccess(`{"profile_id":"01890f00-0000-7000-8000-000000000c01","namespaces":["a"],"mode":"report","report_until":"tomorrow"}`),
		"unknown field":       withAccess(`{"full":true,"wide":true}`),
		"access to a group":   strings.Replace(withAccess(`{"full":true}`), `"destination_kubernetes_cluster_id"`, `"destination_device_group_id"`, 1),
	} {
		if _, failure := decodeAccessPublication(t, `{"reason":"x","rules":[`+body+`]}`); failure == nil ||
			failure.Code != "invalid_request" {
			t.Errorf("%s: %v", name, failure)
		}
	}
	for name, profiles := range map[string]string{
		"no rules":         `[{"id":"01890f00-0000-7000-8000-000000000c01","name":"a","description":""}]`,
		"bad name":         `[{"id":"01890f00-0000-7000-8000-000000000c01","name":"A","description":"","namespaced":[{"resources":["pods"],"apiGroups":[""],"verbs":["get"]}]}]`,
		"unknown rule key": `[{"id":"01890f00-0000-7000-8000-000000000c01","name":"a","description":"","namespaced":[{"resource":["pods"]}]}]`,
		"not a UUIDv7":     `[{"id":"not-an-id","name":"a","description":"","namespaced":[{"resources":["pods"],"apiGroups":[""],"verbs":["get"]}]}]`,
		"null in the list": `[null]`,
	} {
		if _, failure := decodeAccessPublication(t, `{"reason":"x","kubernetes_profiles":`+profiles+`,"rules":[]}`); failure == nil {
			t.Errorf("%s decoded", name)
		}
	}
}

// Each refusal of Kubernetes access has its own code, in publish, simulate
// and approval alike.
func TestKubernetesAccessErrorsHaveCodes(t *testing.T) {
	t.Parallel()
	for err, code := range map[error]string{
		compilation.ErrKubernetesAccessRequired: "kubernetes_access_required",
		compilation.ErrKubernetesProfileUnknown: "kubernetes_profile_unknown",
		compilation.ErrKubernetesProfileInUse:   "kubernetes_profile_in_use",
		compilation.ErrKubernetesReportWindow:   "kubernetes_report_window",
		compilation.ErrKubernetesAccessLimit:    "kubernetes_access_limit",
		compilation.ErrKubernetesGroupsRequired: "kubernetes_groups_required",
		policypublication.ErrKubernetesProfile:  "kubernetes_profile_conflict",
	} {
		wrapped := errors.Join(err, errors.New("detail"))
		for name, answer := range map[string]managementError{
			"compile": classifyPolicyCompilationError(wrapped), "approval": classifyPolicyApprovalError(wrapped),
			"simulation": classifyPolicySimulationError(wrapped),
		} {
			if answer.Code != code {
				t.Errorf("%s %v = %s, want %s", name, err, answer.Code, code)
			}
		}
	}
	if answer := classifyPolicyPublicationError(policypublication.ErrKubernetesProfile); answer.Code !=
		"kubernetes_profile_conflict" || answer.Status != http.StatusConflict {
		t.Fatalf("publication = %+v", answer)
	}
}

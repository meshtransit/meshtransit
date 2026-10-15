package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/guardrail"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	testGuardrailWorkspace = "01890f00-0000-7000-8000-000000000103"
	testGuardrailNetwork   = "01890f00-0000-7000-8000-000000000203"
	testGuardrailID        = "01890f00-0000-7000-8000-000000000901"
	testGuardrailBody      = `{"kind":"network_sharing","name":"Production shares nothing","description":"",` +
		`"mode":"enforce","params":{"networks":["` + testGuardrailNetwork + `"],"direction":"outgoing"}}`
)

type stubGuardrails struct {
	impact    guardrail.Impact
	err       error
	candidate guardrail.Candidate
	hash      guardrail.ImpactHash
	deleted   bool
}

func (stub *stubGuardrails) List(context.Context, accountsession.Session, workspace.ID) (guardrail.Listing, error) {
	return guardrail.Listing{}, stub.err
}

func (stub *stubGuardrails) Preview(_ context.Context, _ accountsession.Session, _ workspace.ID,
	candidate guardrail.Candidate) (guardrail.Impact, error) {
	stub.candidate = candidate
	return stub.impact, stub.err
}

func (stub *stubGuardrails) result(spec guardrail.Spec) (guardrail.Result, error) {
	if stub.err != nil {
		return guardrail.Result{}, stub.err
	}
	id, _ := publicid.Parse(testGuardrailID)
	return guardrail.Result{Guardrail: guardrail.Guardrail{ID: id, Version: 1, Spec: spec}, Deleted: stub.deleted}, nil
}

func (stub *stubGuardrails) Create(_ context.Context, _ accountsession.Session, _ workspace.ID, spec guardrail.Spec,
	hash guardrail.ImpactHash, _ publicid.ID) (guardrail.Result, error) {
	stub.hash = hash
	return stub.result(spec)
}

func (stub *stubGuardrails) Update(_ context.Context, _ accountsession.Session, _ workspace.ID, _ publicid.ID, _ int64,
	spec guardrail.Spec, hash guardrail.ImpactHash, _ publicid.ID) (guardrail.Result, error) {
	stub.hash = hash
	return stub.result(spec)
}

func (stub *stubGuardrails) Delete(context.Context, accountsession.Session, workspace.ID, publicid.ID, int64,
	publicid.ID) (guardrail.Result, error) {
	stub.deleted = true
	networkID, _ := network.ParseID(testGuardrailNetwork)
	return stub.result(guardrail.Spec{Kind: guardrail.KindNetworkSharing, Name: "Production shares nothing",
		Mode: guardrail.ModeEnforce, Sharing: guardrail.NetworkSharingParams{
			Networks: []network.ID{networkID}, Direction: guardrail.DirectionOutgoing}})
}

func serveGuardrail(t *testing.T, stub *stubGuardrails, target, body string, ifMatch string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/api/v1/workspaces/"+testGuardrailWorkspace+"/guardrails"+target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	path, ok := parseGuardrailPath(request)
	if !ok {
		t.Fatalf("%s: path not matched", target)
	}
	correlation, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	handler := &ManagementHandler{logger: slog.New(slog.DiscardHandler), guardrails: stub}
	recorder := httptest.NewRecorder()
	handler.handleGuardrails(t.Context(), recorder, request, correlation, path, accountsession.Session{})
	return recorder
}

func TestParseGuardrailPathPreview(t *testing.T) {
	t.Parallel()
	base := "/api/v1/workspaces/" + testGuardrailWorkspace + "/guardrails"
	for target, want := range map[string]string{
		base: "", base + "/actions/create": "create", base + "/actions/preview": "preview",
		base + "/" + testGuardrailID + "/actions/update": "update",
	} {
		path, ok := parseGuardrailPath(httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, nil))
		if !ok || path.action != want {
			t.Errorf("%s: %+v %v", target, path, ok)
		}
	}
	for _, target := range []string{base + "/actions/previews", base + "/" + testGuardrailID + "/actions/preview"} {
		if _, ok := parseGuardrailPath(httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, nil)); ok {
			t.Errorf("%s: matched", target)
		}
	}
	preview := httptest.NewRequestWithContext(t.Context(), http.MethodGet, base+"/actions/preview", nil)
	if isGuardrailOperation(preview) || parsedOperation(t, base+"/actions/preview") != guardrailPreviewOperation {
		t.Fatal("preview must be a POST operation of its own")
	}
}

func parsedOperation(t *testing.T, target string) string {
	t.Helper()
	path, _ := parseGuardrailPath(httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, nil))
	return path.operation(http.MethodPost)
}

func TestGuardrailPreviewResponse(t *testing.T) {
	t.Parallel()
	contracts := make([]guardrail.ShareContract, guardrail.MaximumPreviewItems+44)
	networkID, _ := network.ParseID(testGuardrailNetwork)
	for index := range contracts {
		id, err := publicid.New()
		if err != nil {
			t.Fatal(err)
		}
		contracts[index] = guardrail.ShareContract{ID: id, Side: guardrail.SideProvider, NetworkID: networkID,
			Label: "db"}
	}
	stub := &stubGuardrails{impact: guardrail.Impact{Mode: guardrail.ModeEnforce, Affected: contracts,
		Hash: guardrail.ImpactHash{1, 2, 3}}}
	update := strings.Replace(testGuardrailBody, `{"kind"`, `{"guardrail_id":"`+testGuardrailID+`","expected_version":2,"kind"`, 1)
	recorder := serveGuardrail(t, stub, "/actions/preview", update, "")
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body.String())
	}
	var body struct {
		Data struct {
			Mode          string `json:"mode"`
			AffectedCount int    `json:"affected_count"`
			Affected      []struct {
				TrustContractID string `json:"trust_contract_id"`
				Side            string `json:"side"`
				NetworkID       string `json:"network_id"`
				Label           string `json:"label"`
			} `json:"affected"`
			Truncated  bool   `json:"truncated"`
			ImpactHash string `json:"impact_hash"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	data := body.Data
	if data.Mode != "enforce" || data.AffectedCount != len(contracts) || len(data.Affected) != guardrail.MaximumPreviewItems ||
		!data.Truncated || data.ImpactHash != stub.impact.Hash.String() || data.Affected[0].Side != "provider" ||
		data.Affected[0].NetworkID != testGuardrailNetwork || data.Affected[0].TrustContractID != contracts[0].ID.String() {
		t.Fatalf("preview body = %s", recorder.Body.String())
	}
	if stub.candidate.GuardrailID.String() != testGuardrailID || stub.candidate.ExpectedVersion != 2 ||
		stub.candidate.Spec.Mode != guardrail.ModeEnforce {
		t.Fatalf("candidate = %+v", stub.candidate)
	}
	// Nothing affected is an empty list, not null.
	empty := &stubGuardrails{impact: guardrail.Impact{Mode: guardrail.ModeAudit, Affected: []guardrail.ShareContract{}}}
	if recorder := serveGuardrail(t, empty, "/actions/preview", testGuardrailBody, ""); recorder.Code != http.StatusOK ||
		!strings.Contains(recorder.Body.String(), `"affected":[]`) || !strings.Contains(recorder.Body.String(), `"truncated":false`) {
		t.Fatalf("empty preview = %s", recorder.Body.String())
	}
}

func TestGuardrailRequestFields(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("ab", 32)
	withHash := strings.Replace(testGuardrailBody, `{"kind"`, `{"impact_hash":"`+hash+`","kind"`, 1)
	withID := strings.Replace(testGuardrailBody, `{"kind"`, `{"guardrail_id":"`+testGuardrailID+`","expected_version":1,"kind"`, 1)
	for _, test := range []struct {
		name, body string
		preview    bool
		valid      bool
	}{
		{name: "save with hash", body: withHash, valid: true},
		{name: "save without hash", body: testGuardrailBody, valid: true},
		{name: "preview of a new guardrail", body: testGuardrailBody, preview: true, valid: true},
		{name: "preview of an update", body: withID, preview: true, valid: true},
		{name: "preview with a hash", body: withHash, preview: true},
		{name: "save naming a guardrail", body: withID},
		{name: "id without version", preview: true,
			body: strings.Replace(withID, `"expected_version":1,`, "", 1)},
		{name: "zero version", preview: true, body: strings.Replace(withID, `"expected_version":1`, `"expected_version":0`, 1)},
		{name: "upper-case hash", body: strings.Replace(withHash, hash, strings.ToUpper(hash), 1)},
		{name: "short hash", body: strings.Replace(withHash, hash, hash[2:], 1)},
	} {
		request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(test.body))
		request.Header.Set("Content-Type", "application/json")
		parsed, ok := parseGuardrailRequest(httptest.NewRecorder(), request, test.preview)
		if ok != test.valid {
			t.Errorf("%s: valid = %v", test.name, ok)
		}
		if ok && test.body == withHash && parsed.impact.String() != hash {
			t.Errorf("%s: hash %s", test.name, parsed.impact)
		}
	}
}

func TestGuardrailSaveCarriesTheImpactHash(t *testing.T) {
	t.Parallel()
	hash := strings.Repeat("0f", 32)
	body := strings.Replace(testGuardrailBody, `{"kind"`, `{"impact_hash":"`+hash+`","kind"`, 1)
	stub := &stubGuardrails{}
	if recorder := serveGuardrail(t, stub, "/actions/create", body, ""); recorder.Code != http.StatusCreated ||
		stub.hash.String() != hash {
		t.Fatalf("create: %d, hash %s", recorder.Code, stub.hash)
	}
	stub = &stubGuardrails{}
	if recorder := serveGuardrail(t, stub, "/"+testGuardrailID+"/actions/update", body, `"1"`); recorder.Code != http.StatusOK ||
		stub.hash.String() != hash {
		t.Fatalf("update: %d, hash %s", recorder.Code, stub.hash)
	}
	// A missing or stale hash comes back as a 409 the Console can act on.
	stale := &stubGuardrails{err: guardrail.ErrImpactChanged}
	for target, ifMatch := range map[string]string{"/actions/create": "", "/" + testGuardrailID + "/actions/update": `"1"`} {
		recorder := serveGuardrail(t, stale, target, testGuardrailBody, ifMatch)
		if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), `"guardrail_impact_changed"`) {
			t.Fatalf("%s: %d %s", target, recorder.Code, recorder.Body.String())
		}
	}
	// Deleting only restores shares: no body, no hash.
	deletion := &stubGuardrails{}
	if recorder := serveGuardrail(t, deletion, "/"+testGuardrailID+"/actions/delete", "", `"1"`); recorder.Code != http.StatusOK ||
		!deletion.deleted {
		t.Fatalf("delete: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestClassifyGuardrailError(t *testing.T) {
	t.Parallel()
	for err, want := range map[error]struct {
		code   string
		status int
	}{
		guardrail.ErrImpactChanged:  {"guardrail_impact_changed", http.StatusConflict},
		guardrail.ErrImpactTooLarge: {"guardrail_impact_too_large", http.StatusUnprocessableEntity},
		guardrail.ErrForbidden:      {"permission_denied", http.StatusForbidden},
		guardrail.ErrNotFound:       {"guardrail_not_found", http.StatusNotFound},
		guardrail.ErrInvalid:        {"invalid_request", http.StatusBadRequest},
		// An internal inconsistency is never blamed on the request.
		errors.Join(guardrail.ErrUnavailable, guardrail.ErrInvalid): {"temporarily_unavailable", http.StatusServiceUnavailable},
	} {
		if got := classifyGuardrailError(err); got.Code != want.code || got.Status != want.status {
			t.Errorf("%v: %s %d, want %s %d", err, got.Code, got.Status, want.code, want.status)
		}
	}
}

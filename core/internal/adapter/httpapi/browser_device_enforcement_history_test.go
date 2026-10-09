package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/core/internal/domain/node/enforcementledger"
	"meshtransit.net/shared/policydigest"
)

type enforcementHistoryTestReader struct {
	result enforcementledger.HistoryResult
	err    error
	reads  int
	at     time.Time
}

func (reader *enforcementHistoryTestReader) ReadEnforcementHistory(_ context.Context, _ accountsession.Session,
	scope network.Scope, at time.Time, _ node.ID, _ int, _ time.Time) (enforcementledger.HistoryResult, error) {
	reader.reads++
	reader.at = at
	result := reader.result
	result.Scope, result.At = scope, at
	return result, reader.err
}

func enforcementHistoryTestPath() string {
	return deviceInventoryTestPath() + "/enforcement-history"
}

func TestBrowserEnforcementHistoryReadsEvidenceAtAnInstant(t *testing.T) {
	t.Parallel()
	options, fixture := browserManagementTestOptions(t)
	at := fixture.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	request := browserManagementReadRequest(t, enforcementHistoryTestPath()+"?at="+at.Format(time.RFC3339Nano))
	if _, ok := parseEnforcementHistoryPath(request); !ok {
		t.Fatal("valid exact scope rejected")
	}
	if _, distributionMatched := parseDeviceDistributionPath(request); distributionMatched {
		t.Fatal("enforcement history matched the distribution route")
	}
	device, _ := node.ParseID("01890f00-0000-7000-8000-000000000301")
	delivered, enforced := policydigest.Digest{0xa}, policydigest.Digest{0xb}
	validFrom := at.Add(-time.Minute)
	reader := &enforcementHistoryTestReader{result: enforcementledger.HistoryResult{
		RecordedSince: validFrom,
		Devices: []enforcementledger.Evidence{{
			DeviceID: device, Hostname: "poc-02-1", State: enforcementledger.StateMismatch, NetworkRevision: 10,
			Delivered: distribution.FilterSummary{Digest: delivered, Grants: 8},
			Enforced:  distribution.FilterSummary{Digest: enforced, Grants: 0},
			AppliedAt: validFrom.Add(-2 * time.Second), ReportedAt: validFrom.Add(-time.Second), ValidFrom: validFrom,
			ValidTo: at.Add(time.Minute),
		}},
	}}
	service, err := enforcementledger.NewHistoryService(reader, fixture)
	if err != nil {
		t.Fatal(err)
	}
	options.EnforcementHistory = service
	browser, err := NewBrowserManagement(options)
	if err != nil {
		t.Fatal(err)
	}
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || reader.reads != 1 || !reader.at.Equal(at) ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("enforcement history bypassed the private read contract", response.Code, response.Body.String())
	}
	var envelope enforcementHistoryEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	data := envelope.Data
	if !data.At.Equal(at) || data.RecordedSince == nil || len(data.Devices) != 1 {
		t.Fatalf("history = %+v", data)
	}
	item := data.Devices[0]
	if item.State != "mismatch" || item.DeliveredDigest != delivered.String() || item.EnforcedDigest != enforced.String() ||
		item.DeliveredGrants != 8 || item.EnforcedGrants != 0 || item.Hostname == nil || *item.Hostname != "poc-02-1" ||
		item.ValidTo == nil {
		t.Fatalf("evidence = %+v", item)
	}

	reader.err = enforcementledger.ErrForbidden
	response = &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "poc-02-1") {
		t.Fatal("denied read disclosed evidence")
	}
	future := browserManagementReadRequest(t,
		enforcementHistoryTestPath()+"?at="+fixture.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano))
	response = &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, future); err != nil || response.Code != http.StatusBadRequest {
		t.Fatalf("future instant answered %d, %v", response.Code, err)
	}
}

func TestEnforcementHistoryQueryPinsTheInstantAndScope(t *testing.T) {
	t.Parallel()
	request := browserManagementReadRequest(t, enforcementHistoryTestPath())
	scope, _ := parseEnforcementHistoryPath(request)
	at := time.Date(2026, time.October, 9, 16, 21, 0, 0, time.UTC)
	device, _ := node.ParseID("01890f00-0000-7000-8000-000000000301")
	token, err := encodeEnforcementHistoryPageToken(scope, at, device)
	if err != nil {
		t.Fatal(err)
	}
	query, err := parseEnforcementHistoryQuery("page_token="+token, scope)
	if err != nil || !query.at.Equal(at) || query.after != device || query.limit != 50 {
		t.Fatalf("own cursor = %+v %v", query, err)
	}
	if _, err := parseEnforcementHistoryQuery("at=2026-10-09T16:22:00Z&page_token="+token, scope); err == nil {
		t.Fatal("a cursor moved to another instant")
	}
	otherRequest := browserManagementReadRequest(t,
		strings.Replace(enforcementHistoryTestPath(), "000000000201", "000000000202", 1))
	otherScope, _ := parseEnforcementHistoryPath(otherRequest)
	if _, err := parseEnforcementHistoryQuery("page_token="+token, otherScope); err == nil {
		t.Fatal("cross-Network cursor accepted")
	}
	for _, raw := range []string{"page_size=101", "page_size=01", "at=yesterday", "device=x", "at=", "page_token="} {
		if _, err := parseEnforcementHistoryQuery(raw, scope); !errors.Is(err, enforcementledger.ErrInvalidRequest) {
			t.Errorf("query %q accepted: %v", raw, err)
		}
	}
}

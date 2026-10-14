package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/addressusage"
	"meshtransit.net/core/internal/domain/publicid"
)

func TestParseNetworkAddressUsagePath(t *testing.T) {
	t.Parallel()
	base := "/api/v1/workspaces/" + aliasRangeWorkspace + "/networks/" + aliasRangeNetwork + "/address-usage"
	for _, test := range []struct {
		name, method, target string
		matched, read        bool
	}{
		{name: "read", method: http.MethodGet, target: base, matched: true, read: true},
		{name: "post", method: http.MethodPost, target: base, matched: true},
		{name: "query", method: http.MethodGet, target: base + "?x=1"},
		{name: "sub-path", method: http.MethodGet, target: base + "/x"},
		{name: "not a v7 id", method: http.MethodGet,
			target: "/api/v1/workspaces/01890f00-0000-4000-8000-000000000101/networks/" + aliasRangeNetwork + "/address-usage"},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.target, nil)
		if _, matched := parseNetworkAddressUsagePath(request); matched != test.matched {
			t.Errorf("%s: matched = %v", test.name, matched)
		}
		if isNetworkAddressUsageRead(request) != test.read {
			t.Errorf("%s: read admitted = %v", test.name, !test.read)
		}
	}
}

type stubAddressUsage struct {
	state addressusage.State
	err   error
}

func (stub stubAddressUsage) Read(context.Context, accountsession.Session, network.Scope) (addressusage.State, error) {
	return stub.state, stub.err
}

func TestReadNetworkAddressUsage(t *testing.T) {
	t.Parallel()
	release := time.Date(2026, 10, 15, 8, 30, 0, 0, time.UTC)
	stub := stubAddressUsage{state: addressusage.State{Ranges: []addressusage.Range{
		{Prefix: netip.MustParsePrefix("100.80.0.0/16"), Capacity: 65534, InUse: 12, HeldByExpired: 1,
			HeldAfterRevocation: 2, NextRelease: release},
		{Prefix: netip.MustParsePrefix("fd07:d4de:9d87::/64"), InUse: 12},
	}}}
	handler := &ManagementHandler{logger: slog.New(slog.DiscardHandler), addressUsage: stub}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/api/v1/workspaces/"+aliasRangeWorkspace+"/networks/"+aliasRangeNetwork+"/address-usage", nil)
	scope, ok := parseNetworkAddressUsagePath(request)
	if !ok {
		t.Fatal("path not matched")
	}
	correlation, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	if code := handler.readNetworkAddressUsage(t.Context(), recorder, correlation, scope, accountsession.Session{}); code != "success" ||
		recorder.Code != http.StatusOK {
		t.Fatalf("result %q, status %d", code, recorder.Code)
	}
	var body struct {
		Data struct {
			NetworkID string `json:"network_id"`
			Ranges    []struct {
				Family              int        `json:"family"`
				Prefix              string     `json:"prefix"`
				Capacity            *int64     `json:"capacity"`
				InUse               int64      `json:"in_use"`
				HeldByExpired       int64      `json:"held_by_expired"`
				HeldAfterRevocation int64      `json:"held_after_revocation"`
				NextRelease         *time.Time `json:"next_release"`
			} `json:"ranges"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	ranges := body.Data.Ranges
	if body.Data.NetworkID != aliasRangeNetwork || len(ranges) != 2 ||
		ranges[0].Family != 4 || ranges[0].Capacity == nil || *ranges[0].Capacity != 65534 ||
		ranges[0].HeldAfterRevocation != 2 || ranges[0].NextRelease == nil || !ranges[0].NextRelease.Equal(release) ||
		ranges[1].Family != 6 || ranges[1].Capacity != nil || ranges[1].NextRelease != nil {
		t.Fatalf("body = %s", recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("address usage must not be cached")
	}
	// A refusal is a 403, a store failure a retryable 503.
	for err, status := range map[error]int{
		addressusage.ErrForbidden:   http.StatusForbidden,
		addressusage.ErrUnavailable: http.StatusServiceUnavailable,
		errors.New("anything"):      http.StatusServiceUnavailable,
	} {
		handler.addressUsage = stubAddressUsage{err: err}
		recorder := httptest.NewRecorder()
		handler.readNetworkAddressUsage(t.Context(), recorder, correlation, scope, accountsession.Session{})
		if recorder.Code != status {
			t.Errorf("%v: status %d, want %d", err, recorder.Code, status)
		}
	}
}

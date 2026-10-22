package httpapi

import (
	"errors"
	"net/http"
	"testing"

	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/sharing"
)

type fakeServiceNameChecker map[string]string

func (checker fakeServiceNameChecker) ServiceName(value string) (string, bool, error) {
	canonical, found := checker[value]
	if !found {
		return "", false, dnszone.ErrDomainSpecialUse
	}
	return canonical, canonical == "app.corp.com", nil
}

func TestParseOfferServiceNames(t *testing.T) {
	t.Parallel()
	handler := &ManagementHandler{serviceNames: fakeServiceNameChecker{
		"App.Corp.com": "app.corp.com", "app.corp.com": "app.corp.com", "wiki.corp.lan": "wiki.corp.lan",
		"WIKI.corp.lan": "wiki.corp.lan",
	}}
	names, failure := handler.parseOfferServiceNames([]string{"App.Corp.com", "wiki.corp.lan"})
	if failure != nil || len(names) != 2 || names[0].String() != "app.corp.com" {
		t.Fatalf("names = %v, %+v", names, failure)
	}
	if data := handler.serviceNameData(names); len(data) != 2 || !data[0].Public || data[1].Public {
		t.Fatalf("data = %+v", data)
	}
	if _, failure := handler.parseOfferServiceNames([]string{"wiki.corp.lan", "app.local"}); failure == nil ||
		failure.Code != "dns_zone_special_use" || failure.OperationIndex == nil || *failure.OperationIndex != 1 {
		t.Fatalf("a refused name = %+v", failure)
	}
	if _, failure := handler.parseOfferServiceNames([]string{"wiki.corp.lan", "WIKI.corp.lan"}); failure == nil ||
		failure.OperationIndex == nil || *failure.OperationIndex != 1 {
		t.Fatalf("a name twice = %+v", failure)
	}
	nine := make([]string, 9)
	if _, failure := handler.parseOfferServiceNames(nine); failure == nil || failure.Code != "dns_service_name_limit" {
		t.Fatalf("nine names = %+v", failure)
	}
	if _, failure := (&ManagementHandler{}).parseOfferServiceNames([]string{"app.corp.com"}); failure == nil ||
		failure.Code != "dns_zones_disabled" {
		t.Fatalf("no checker = %+v", failure)
	}
	if names, failure := (&ManagementHandler{}).parseOfferServiceNames(nil); failure != nil || names != nil {
		t.Fatal("no names need no checker")
	}
}

func TestParseServiceNameDecisions(t *testing.T) {
	t.Parallel()
	decisions, ok := parseServiceNameDecisions([]serviceNameDecisionRequest{
		{Name: "app.corp.com", Decision: "approve"}, {Name: "wiki.corp.lan", Decision: "decline"},
	})
	if !ok || len(decisions) != 2 || !decisions[0].Approve || decisions[1].Approve {
		t.Fatalf("decisions = %+v, %v", decisions, ok)
	}
	for name, values := range map[string][]serviceNameDecisionRequest{
		"no decision":   {{Name: "app.corp.com"}},
		"other answer":  {{Name: "app.corp.com", Decision: "yes"}},
		"not canonical": {{Name: "App.corp.com", Decision: "approve"}},
	} {
		if _, ok := parseServiceNameDecisions(values); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestClassifySharingErrorNamesTheServiceName(t *testing.T) {
	t.Parallel()
	taken := classifySharingError(errors.Join(sharing.ErrConflict,
		&sharing.ServiceNameError{Index: 2, Err: dnszone.ErrNameTaken}))
	if taken.Status != http.StatusConflict || taken.Code != "dns_name_conflict" || taken.OperationIndex == nil ||
		*taken.OperationIndex != 2 {
		t.Fatalf("a taken service name = %+v", taken)
	}
	if missing := classifySharingError(sharing.ErrServiceNameDecisions); missing.Status != http.StatusBadRequest ||
		missing.Code != "dns_service_name_decision_missing" {
		t.Fatalf("missing decisions = %+v", missing)
	}
}

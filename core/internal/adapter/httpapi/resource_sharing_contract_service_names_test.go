package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/sharing"
)

type contractServiceNamesStub struct {
	read    func(network.Scope, sharing.ContractID) (sharing.ContractServiceNames, error)
	replace func(network.Scope, sharing.ContractID, int64, []sharing.ServiceName) (sharing.ContractServiceNames, error)
	use     func(network.Scope, sharing.ContractID, sharing.ServiceName) (dnszone.Name, dnszone.Zone, error)
}

func (stub contractServiceNamesStub) ContractServiceNames(_ context.Context, _ accountsession.Session,
	scope network.Scope, id sharing.ContractID,
) (sharing.ContractServiceNames, error) {
	return stub.read(scope, id)
}

func (stub contractServiceNamesStub) ReplaceContractServiceNames(_ context.Context, _ accountsession.Session,
	scope network.Scope, id sharing.ContractID, version int64, names []sharing.ServiceName, _ publicid.ID,
) (sharing.ContractServiceNames, bool, error) {
	result, err := stub.replace(scope, id, version, names)
	return result, err == nil, err
}

func (stub contractServiceNamesStub) UseContractServiceName(_ context.Context, _ accountsession.Session,
	scope network.Scope, id sharing.ContractID, name sharing.ServiceName, _ publicid.ID,
) (dnszone.Name, dnszone.Zone, error) {
	return stub.use(scope, id, name)
}

func mustServiceName(t *testing.T, value string) sharing.ServiceName {
	t.Helper()
	name, err := sharing.ParseServiceName(value)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func TestParseContractServiceNamesPaths(t *testing.T) {
	t.Parallel()
	base := "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" + managementNetworkID() +
		"/trust-contracts/01890f00-0000-7000-8000-000000000a01"
	for _, test := range []struct {
		path, method, want string
	}{
		{base + "/service-names", http.MethodGet, shareContractServiceNamesGetOperation},
		{base + "/service-names", http.MethodPut, shareContractServiceNamesReplaceOperation},
		{base + "/service-names/actions/use", http.MethodPost, shareContractServiceNameUseOperation},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.path, nil)
		path, matched := parseResourceSharingPath(request)
		if !matched || path.operation(test.method) != test.want || path.allowedMethod(test.method) != test.method {
			t.Errorf("%s %s = %+v, %v", test.method, test.path, path, matched)
		}
	}
	for _, path := range []string{base + "/service-names/actions/drop", base + "/names",
		base + "/service-names/x/use", "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" +
			managementNetworkID() + "/share-offers/01890f00-0000-7000-8000-000000000a01/service-names"} {
		if _, matched := parseResourceSharingPath(httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)); matched {
			t.Errorf("%s matched", path)
		}
	}
	if path, _ := parseResourceSharingPath(httptest.NewRequestWithContext(t.Context(), http.MethodPost, base+"/service-names", nil)); path.allowedMethod(http.MethodPost) != http.MethodGet {
		t.Error("POST on the service names is allowed")
	}
}

func TestManagementHandlerContractServiceNames(t *testing.T) {
	t.Parallel()
	fixture, contract, _ := managementSharingContractFixture(t, sharing.ContractStateActive, 2)
	share := contract.ImportedResourceID()
	parseID := func(value string) publicid.ID {
		id, err := publicid.Parse(value)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	nameID, zoneID := parseID("01890f00-0000-7000-8000-000000000b01"), parseID("01890f00-0000-7000-8000-000000000b02")
	wikiZone, _, err := dnszone.ParseDomain("wiki.corp.lan", dnszone.Names{Suffix: dnsname.Default()})
	if err != nil {
		t.Fatal(err)
	}
	consumerView := sharing.ContractServiceNames{
		ContractID: contract.ID(), State: "active", ExpiresAt: time.Now().Add(time.Hour), Version: 0,
		Names:   []sharing.ServiceName{mustServiceName(t, "app.corp.com"), mustServiceName(t, "wiki.corp.lan")},
		ShareID: share, DNSNames: []sharing.ContractDNSName{{ID: nameID, ZoneID: zoneID, FQDN: "app.corp.com"}},
	}
	providerView := consumerView
	providerView.Provider, providerView.ShareID, providerView.DNSNames = true, sharing.ImportedResourceID{}, nil
	var replaced struct {
		version int64
		names   []sharing.ServiceName
	}
	options := validManagementHandlerOptions(t)
	options.ResourceSharing = &managementResourceSharingStub{}
	options.ServiceNames = fakeServiceNameChecker{"app.corp.com": "app.corp.com", "Shop.Corp.com": "shop.corp.com"}
	options.ContractServiceNames = contractServiceNamesStub{
		read: func(scope network.Scope, id sharing.ContractID) (sharing.ContractServiceNames, error) {
			if id != contract.ID() {
				t.Fatal("another contract read")
			}
			if scope == fixture.provider {
				return providerView, nil
			}
			return consumerView, nil
		},
		replace: func(scope network.Scope, _ sharing.ContractID, version int64, names []sharing.ServiceName,
		) (sharing.ContractServiceNames, error) {
			if scope != fixture.provider {
				return sharing.ContractServiceNames{}, sharing.ErrForbidden
			}
			if version == 7 {
				return sharing.ContractServiceNames{}, sharing.ErrServiceNamesChanged
			}
			replaced.version, replaced.names = version, names
			result := providerView
			result.Version, result.Names = 1, names
			return result, nil
		},
		use: func(_ network.Scope, _ sharing.ContractID, name sharing.ServiceName) (dnszone.Name, dnszone.Zone,
			error,
		) {
			switch name.String() {
			case "wiki.corp.lan":
				return dnszone.Name{ID: dnszone.NameID(nameID), ZoneID: dnszone.ID(zoneID), FQDN: name.String(),
						Version: 1},
					dnszone.Zone{ID: dnszone.ID(zoneID), Domain: wikiZone}, nil
			case "taken.corp.lan":
				return dnszone.Name{}, dnszone.Zone{}, dnszone.ErrNameTaken
			}
			return dnszone.Name{}, dnszone.Zone{}, sharing.ErrServiceNameNotSuggested
		},
	}
	handler, handlerErr := NewManagementHandler(options)
	if handlerErr != nil {
		t.Fatal(handlerErr)
	}
	path := func(scope network.Scope, suffix string) string {
		return "/api/v1/workspaces/" + scope.WorkspaceID().String() + "/networks/" + scope.NetworkID().String() +
			"/trust-contracts/" + contract.ID().String() + "/service-names" + suffix
	}
	serve := func(method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
		request := newManagementRequest(t, method, target, body)
		if body == "" {
			request.Body = http.NoBody
			request.Header.Del("Content-Type")
		}
		request.Header.Del("If-Match")
		request.Header.Del("Idempotency-Key")
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}

	// The consumer reads the suggestions, which one it made, and its names.
	response := serve(http.MethodGet, path(fixture.consumer, ""), "", nil)
	var envelope contractServiceNamesEnvelope
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"0"` ||
		json.Unmarshal(response.Body.Bytes(), &envelope) != nil {
		t.Fatalf("consumer read = %d %s %s", response.Code, response.Header().Get("ETag"), response.Body.String())
	}
	data := envelope.Data
	if data.Side != "consumer" || !data.Running || len(data.ServiceNames) != 2 || !data.ServiceNames[0].Public ||
		data.ServiceNames[0].DNSNameID != nameID.String() || data.ServiceNames[1].DNSNameID != "" ||
		data.DNSNames == nil || len(*data.DNSNames) != 1 {
		t.Fatalf("consumer data = %+v", data)
	}
	// The provider never sees the consumer's names.
	response = serve(http.MethodGet, path(fixture.provider, ""), "", nil)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), "dns_name") ||
		!strings.Contains(response.Body.String(), `"side":"provider"`) {
		t.Fatalf("provider read = %d %s", response.Code, response.Body.String())
	}

	// The provider replaces them at version 0, each name checked as DNS.
	response = serve(http.MethodPut, path(fixture.provider, ""), `{"service_names":["Shop.Corp.com","app.corp.com"]}`,
		map[string]string{"If-Match": `"0"`, "Content-Type": "application/json"})
	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` || replaced.version != 0 ||
		len(replaced.names) != 2 || replaced.names[0].String() != "shop.corp.com" {
		t.Fatalf("replace = %d %s %+v", response.Code, response.Body.String(), replaced)
	}
	for name, test := range map[string]struct {
		body    string
		headers map[string]string
		status  int
		code    string
	}{
		"no precondition": {`{"service_names":[]}`, map[string]string{"Content-Type": "application/json"},
			http.StatusPreconditionRequired, "precondition_required"},
		"a stale version": {`{"service_names":[]}`, map[string]string{"If-Match": `"7"`,
			"Content-Type": "application/json"}, http.StatusPreconditionFailed, "precondition_failed"},
		"a refused name": {`{"service_names":["app.local"]}`, map[string]string{"If-Match": `"1"`,
			"Content-Type": "application/json"}, http.StatusUnprocessableEntity, "dns_zone_special_use"},
		"no list": {`{}`, map[string]string{"If-Match": `"1"`, "Content-Type": "application/json"},
			http.StatusBadRequest, "invalid_request"},
	} {
		response := serve(http.MethodPut, path(fixture.provider, ""), test.body, test.headers)
		if response.Code != test.status || decodeManagementErrorCode(t, response.Body.Bytes()) != test.code {
			t.Errorf("%s: %d %s", name, response.Code, response.Body.String())
		}
	}
	if response := serve(http.MethodPut, path(fixture.consumer, ""), `{"service_names":[]}`,
		map[string]string{"If-Match": `"0"`, "Content-Type": "application/json"}); response.Code != http.StatusForbidden {
		t.Errorf("the consumer replaced the suggestions: %d", response.Code)
	}

	// The consumer uses a suggestion; another name, or one taken, is refused.
	response = serve(http.MethodPost, path(fixture.consumer, "/actions/use"), `{"name":"wiki.corp.lan"}`,
		map[string]string{"Content-Type": "application/json"})
	var used contractServiceNameUseEnvelope
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &used) != nil ||
		used.Data.DNSNameID != nameID.String() || used.Data.Zone != "wiki.corp.lan" {
		t.Fatalf("use = %d %s", response.Code, response.Body.String())
	}
	for name, want := range map[string]string{"shop.corp.com": "dns_service_name_not_suggested",
		"taken.corp.lan": "dns_name_conflict"} {
		response := serve(http.MethodPost, path(fixture.consumer, "/actions/use"), `{"name":"`+name+`"}`,
			map[string]string{"Content-Type": "application/json"})
		if response.Code != http.StatusConflict || decodeManagementErrorCode(t, response.Body.Bytes()) != want {
			t.Errorf("use %s = %d %s", name, response.Code, response.Body.String())
		}
	}
}

package httpapi

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/dnszone"
)

func dnsNameRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost, dnsZoneBase, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func TestParseDNSNameDefinition(t *testing.T) {
	t.Parallel()
	parse := func(body string, create bool) (dnszone.NameDefinition, bool) {
		return parseDNSNameDefinition(httptest.NewRecorder(), dnsNameRequest(t, body), create)
	}
	device, ok := parse(`{"label":"git","kind":"address","device_id":"01890f00-0000-7000-8000-000000000401"}`, true)
	if !ok || device.Label != "git" || device.Kind != dnszone.NameAddress || !device.Target.DeviceID.IsValid() {
		t.Fatalf("a Device name = %+v, %v", device, ok)
	}
	fixed, ok := parse(`{"kind":"address","addresses":["10.0.5.20","2001:db8::1"]}`, false)
	if !ok || fixed.Label != "" || len(fixed.Target.Addresses) != 2 ||
		fixed.Target.Addresses[1] != netip.MustParseAddr("2001:db8::1") {
		t.Fatalf("an update to fixed addresses = %+v, %v", fixed, ok)
	}
	if share, ok := parse(`{"label":"app","kind":"address","share_id":"01890f00-0000-7000-8000-00000000a201"}`,
		true); !ok || share.Target.ShareID.String() != "01890f00-0000-7000-8000-00000000a201" ||
		share.Target.DeviceID.IsValid() {
		t.Fatalf("a share name = %+v, %v", share, ok)
	}
	if alias, ok := parse(`{"label":"wiki","kind":"cname","cname":"Corp.Atlassian.net"}`, true); !ok ||
		alias.Target.CNAME != "Corp.Atlassian.net" {
		t.Fatalf("a CNAME = %+v, %v", alias, ok)
	}
	for name, test := range map[string]struct {
		body   string
		create bool
	}{
		"no label to create":    {`{"kind":"address","addresses":["10.0.5.20"]}`, true},
		"a label to update":     {`{"label":"git","kind":"address","addresses":["10.0.5.20"]}`, false},
		"no kind":               {`{"label":"git","addresses":["10.0.5.20"]}`, true},
		"uncanonical address":   {`{"label":"git","kind":"address","addresses":["010.0.5.20"]}`, true},
		"no addresses":          {`{"label":"git","kind":"address","addresses":[]}`, true},
		"nine addresses":        {`{"label":"git","kind":"address","addresses":["10.0.0.1"` + strings.Repeat(`,"10.0.0.1"`, 8) + `]}`, true},
		"uncanonical Device ID": {`{"label":"git","kind":"address","device_id":"01890F00-0000-7000-8000-000000000401"}`, true},
		"empty CNAME":           {`{"label":"git","kind":"cname","cname":""}`, true},
		"uncanonical share ID":  {`{"label":"app","kind":"address","share_id":"01890F00-0000-7000-8000-00000000A201"}`, true},
		"not a share ID":        {`{"label":"app","kind":"address","share_id":"share-1"}`, true},
		"unknown field":         {`{"label":"git","kind":"cname","cname":"a.example.com","ttl":5}`, true},
	} {
		if _, ok := parse(test.body, test.create); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseDNSNameOperations(t *testing.T) {
	t.Parallel()
	parse := func(body string) ([]dnszone.NameOperation, bool) {
		return parseDNSNameOperations(httptest.NewRecorder(), dnsNameRequest(t, body))
	}
	operations, ok := parse(`{"operations":[` +
		`{"op":"delete","dns_name_id":"01890f00-0000-7000-8000-000000000601","version":3},` +
		`{"op":"create","label":"wiki","kind":"cname","cname":"corp.atlassian.net"},` +
		`{"op":"update","dns_name_id":"01890f00-0000-7000-8000-000000000602","version":1,"kind":"address",` +
		`"addresses":["10.0.5.21"]}]}`)
	if !ok || len(operations) != 3 || operations[0].Operation != dnszone.OperationDelete ||
		operations[0].ExpectedVersion != 3 || operations[1].Definition.Label != "wiki" ||
		operations[1].NameID != (dnszone.NameID{}) || operations[2].Definition.Kind != dnszone.NameAddress {
		t.Fatalf("operations = %+v, %v", operations, ok)
	}
	for name, body := range map[string]string{
		"none":                        `{"operations":[]}`,
		"no op":                       `{"operations":[{"label":"wiki","kind":"cname","cname":"a.example.com"}]}`,
		"a create with an ID":         `{"operations":[{"op":"create","dns_name_id":"01890f00-0000-7000-8000-000000000601","label":"a","kind":"cname","cname":"a.example.com"}]}`,
		"an update without a version": `{"operations":[{"op":"update","dns_name_id":"01890f00-0000-7000-8000-000000000601","kind":"cname","cname":"a.example.com"}]}`,
		"an update with a label":      `{"operations":[{"op":"update","dns_name_id":"01890f00-0000-7000-8000-000000000601","version":1,"label":"a","kind":"cname","cname":"a.example.com"}]}`,
		"a delete with a target":      `{"operations":[{"op":"delete","dns_name_id":"01890f00-0000-7000-8000-000000000601","version":1,"kind":"cname"}]}`,
		"a delete with a share":       `{"operations":[{"op":"delete","dns_name_id":"01890f00-0000-7000-8000-000000000601","version":1,"share_id":"01890f00-0000-7000-8000-00000000a201"}]}`,
		"101 operations": `{"operations":[` + strings.Repeat(`{"op":"delete","dns_name_id":"01890f00-0000-7000-8000-000000000601","version":1},`, 100) +
			`{"op":"delete","dns_name_id":"01890f00-0000-7000-8000-000000000601","version":1}]}`,
	} {
		if _, ok := parse(body); ok {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestClassifyDNSNameErrorNamesTheOperation(t *testing.T) {
	t.Parallel()
	failure := classifyDNSNameError(&dnszone.OperationError{Index: 7, Err: dnszone.ErrCNAMEAtApex})
	if failure.Code != "dns_cname_at_apex" || failure.OperationIndex == nil || *failure.OperationIndex != 7 {
		t.Fatalf("failure = %+v", failure)
	}
	if plain := classifyDNSNameError(dnszone.ErrNameNotFound); plain.OperationIndex != nil ||
		plain.Code != "dns_name_not_found" {
		t.Fatalf("plain = %+v", plain)
	}
}

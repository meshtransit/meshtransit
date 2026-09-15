package legacyts2021

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/internal/node"
)

const mapEndpointFields = `
  "DiscoKey":"discokey:1111111111111111111111111111111111111111111111111111111111111111",
  "Endpoints":["192.0.2.10:41641","10.0.0.2:41641"],
  "EndpointTypes":[2,1],`

func TestDecodeMapRequestTranslatesCanonicalEndpointSet(t *testing.T) {
	t.Parallel()

	body := strings.Replace(mapRequestBody, `  "Stream":false,`, mapEndpointFields+`  "Stream":false,`, 1)
	request, streaming, err := DecodeMapRequest(strings.NewReader(body))
	if err != nil {
		t.Fatalf("DecodeMapRequest() error = %v", err)
	}
	set, present := request.EndpointSet()
	if streaming || !present || !set.IsValid() {
		t.Fatalf("DecodeMapRequest() = (%+v, %t), want endpoint update", request, streaming)
	}
	endpoints := set.Endpoints()
	if len(endpoints) != 2 || endpoints[0].Address().String() != "10.0.0.2:41641" ||
		endpoints[0].Source() != node.EndpointSourceLocal ||
		endpoints[1].Address().String() != "192.0.2.10:41641" ||
		endpoints[1].Source() != node.EndpointSourceSTUN {
		t.Fatalf("EndpointSet.Endpoints() = %+v, want canonical endpoint set", endpoints)
	}
}

func TestDecodeMapRequestTreatsModernStreamAsReadOnly(t *testing.T) {
	t.Parallel()

	body := strings.Replace(mapRequestBody, `  "Stream":false,`, mapEndpointFields+`  "Stream":true,`, 1)
	request, streaming, err := DecodeMapRequest(strings.NewReader(body))
	if err != nil {
		t.Fatalf("DecodeMapRequest() error = %v", err)
	}
	if _, present := request.EndpointSet(); !streaming || present {
		t.Fatalf("DecodeMapRequest() endpoint presence = %t, streaming = %t; want read-only stream", present, streaming)
	}
}

func TestDecodeMapRequestAcceptsEndpointOnlyUpdateMode(t *testing.T) {
	t.Parallel()

	body := strings.Replace(mapRequestBody, `  "Stream":false,`, mapEndpointFields+`  "Stream":false,`, 1)
	body = strings.Replace(body, `"OmitPeers":false`, `"OmitPeers":true`, 1)
	request, streaming, err := DecodeMapRequest(strings.NewReader(body))
	if err != nil {
		t.Fatalf("DecodeMapRequest() error = %v", err)
	}
	if _, present := request.EndpointSet(); streaming || !present {
		t.Fatalf("DecodeMapRequest() endpoint presence = %t, streaming = %t; want endpoint-only update", present, streaming)
	}
}

func TestDecodeMapRequestAcceptsMeshDUncompressedEndpointUpdate(t *testing.T) {
	t.Parallel()

	// meshd@78cb513 intentionally omits Compress and consumes uncompressed map
	// frames. Keep this synthetic fixture aligned with that pinned wire contract.
	body := strings.Replace(mapRequestBody, `  "Compress":"zstd",`+"\n", "", 1)
	body = strings.Replace(body, `  "Stream":false,`, mapEndpointFields+`  "Stream":false,`, 1)
	body = strings.Replace(body, `"OmitPeers":false`, `"OmitPeers":true`, 1)
	request, streaming, err := DecodeMapRequest(strings.NewReader(body))
	if err != nil {
		t.Fatalf("DecodeMapRequest() error = %v", err)
	}
	if _, present := request.EndpointSet(); streaming || !present {
		t.Fatalf(
			"DecodeMapRequest() endpoint presence = %t, streaming = %t; want meshd endpoint update",
			present,
			streaming,
		)
	}
}

func TestDecodeMapRequestRejectsInvalidEndpointReports(t *testing.T) {
	t.Parallel()

	valid := strings.Replace(mapRequestBody, `  "Stream":false,`, mapEndpointFields+`  "Stream":false,`, 1)
	tooMany := make([]string, 65)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf(`"192.0.2.%d:41641"`, index+1)
	}
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "missing discovery key", body: strings.Replace(valid, `  "DiscoKey":"discokey:1111111111111111111111111111111111111111111111111111111111111111",`+"\n", "", 1)},
		{name: "missing endpoint types", body: strings.Replace(valid, `"EndpointTypes":[2,1]`, `"EndpointTypes":[]`, 1)},
		{name: "unknown endpoint type", body: strings.Replace(valid, `"EndpointTypes":[2,1]`, `"EndpointTypes":[2,99]`, 1)},
		{name: "duplicate endpoint", body: strings.Replace(valid, `"10.0.0.2:41641"`, `"192.0.2.10:41641"`, 1)},
		{name: "zero port", body: strings.Replace(valid, `192.0.2.10:41641`, `192.0.2.10:0`, 1)},
		{name: "omit peers without update", body: strings.Replace(mapRequestBody, `"OmitPeers":false`, `"OmitPeers":true`, 1)},
		{name: "omit peers on stream", body: strings.Replace(strings.Replace(valid, `"Stream":false`, `"Stream":true`, 1), `"OmitPeers":false`, `"OmitPeers":true`, 1)},
		{name: "too many endpoints", body: strings.Replace(valid, `"Endpoints":["192.0.2.10:41641","10.0.0.2:41641"]`, `"Endpoints":[`+strings.Join(tooMany, ",")+`]`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := DecodeMapRequest(strings.NewReader(test.body)); !errors.Is(err, ErrInvalidMapRequest) {
				t.Fatalf("DecodeMapRequest() error = %v, want ErrInvalidMapRequest", err)
			}
		})
	}
}
